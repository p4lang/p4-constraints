// Copyright 2020 The P4-Constraints Authors
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "p4_constraints/frontend/parser.h"

#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "gutil/status.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/frontend/ast_constructors.h"
#include "p4_constraints/frontend/constraint_kind.h"
#include "p4_constraints/frontend/lexer.h"
#include "p4_constraints/frontend/token.h"
#include "p4_constraints/quote.h"

namespace p4_constraints {

namespace {

using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::SourceLocation;

// -- Infinite token stream ----------------------------------------------------

// For the purposes of parsing, it is convenient to model the input as an
// infinite stream of tokens (ending in infinitely many END_OF_INPUT tokens).
class TokenStream {
 public:
  explicit TokenStream(const std::vector<Token>& tokens,
                       const ConstraintSource& source)
      : tokens_{tokens}, source_(source) {}
  // Returns next token in stream.
  Token Peek() const;
  // Consumes and returns next token in stream, advancing the stream by 1.
  Token Next();

  const ConstraintSource& source() const { return source_; }

 private:
  const std::vector<Token>& tokens_;
  const ConstraintSource& source_;
  int index_ = 0;
};

Token TokenStream::Peek() const {
  if (index_ < tokens_.size()) return tokens_[index_];
  // If we have exhausted all proper tokens, emit END_OF_INPUT token.
  ast::SourceLocation eof_loc =
      tokens_.empty() ? ast::SourceLocation() : tokens_.back().end_location;
  return Token(Token::END_OF_INPUT, "", eof_loc, eof_loc);
}

Token TokenStream::Next() {
  Token token = Peek();
  ++index_;
  return token;
}

// -- Asociativity & Precedence ------------------------------------------------

// Associativity of binary operators. None-associative operators always require
// parenthesis for disambiguation. E.g., supposing '*' is non-associative:
//   - a * b * c    // parse error
//   - (a * b) * c  // ok
//   - a * (b * c)  // ok
enum class Associativity { LEFT, RIGHT, NONE };

/*constexpr*/  // Waiting for C++17.
Associativity TokenAssociativity(Token::Kind kind) {
  switch (kind) {
    case Token::AND:
    case Token::OR:
    case Token::DOUBLE_COLON:
    case Token::SEMICOLON:
      return Associativity::LEFT;
    // While the convention in logic and functional programming is for `->` to
    // be right-associative, this will likely do more harm than good. Forcing
    // the user to disambiguate using parentheses seems far better, for our
    // purposes.
    // case Token::IMPLIES:
    //   return Associativity::RIGHT;
    default:
      return Associativity::NONE;
  }
}

// Returns an integer encoding the precedence of the given token kind. Higher
// value means "binds stronger". Tokens of the same precedence must have the
// same associativity.
/*constexpr*/  // Waiting for C++17.
int TokenPrecedence(Token::Kind kind) {
  switch (kind) {
    case Token::DOUBLE_COLON:
      return 7;
    case Token::BANG:
    case Token::MINUS:
      return 6;
    case Token::EQ:
    case Token::NE:
    case Token::GT:
    case Token::GE:
    case Token::LT:
    case Token::LE:
      return 5;
    case Token::AND:
      return 4;
    case Token::OR:
      return 3;
    case Token::IMPLIES:
      return 2;
    case Token::SEMICOLON:
      return 1;
    default:
      LOG(ERROR) << "Precedence for token " << kind
                 << "undeclared. Assuming 0.";
      return 0;
  }
}

// -- Error handling -----------------------------------------------------------

gutil::StatusBuilder ParseError(const ConstraintSource& source,
                                const SourceLocation& start,
                                const SourceLocation& end) {
  absl::StatusOr<std::string> quote = QuoteSubConstraint(source, start, end);
  if (!quote.ok()) {
    return gutil::InternalErrorBuilder()
           << "Failed to quote sub-constraint: "
           << gutil::StableStatusToString(quote.status());
  }
  return gutil::InvalidArgumentErrorBuilder() << *quote << "Parse error: ";
}

gutil::StatusBuilder ParseError(Token token, const ConstraintSource& source) {
  return ParseError(source, token.start_location, token.end_location);
}

// Returns an error status indicating that the given token came as a surprise,
// since one of the given other tokens was expected.
absl::Status Unexpected(Token token, const std::vector<Token::Kind>& expected,
                        const ConstraintSource& source) {
  gutil::StatusBuilder error = ParseError(token, source);
  if (token.kind == Token::UNEXPECTED_CHAR) {
    // Slightly awkward phrasing because the unexpected character may actually
    // be further back in the input, see "known limitation" in lexer.h.
    return error << "unexpected character at or after '" << token.text << "'.";
  }

  std::string unexpected_token_str =
      absl::StrCat("unexpected token: ", Token::KindToKeyword(token.kind), ".");
  for (int i = 0; i < expected.size(); i++) {
    if (i == 0) {
      absl::StrAppend(&unexpected_token_str, " Expected ",
                      Token::KindToKeyword(expected[i]));
    } else if (i == expected.size() - 1) {
      absl::StrAppend(&unexpected_token_str, ", or ",
                      Token::KindToKeyword(expected[i]));
    } else {
      absl::StrAppend(&unexpected_token_str, ", ",
                      Token::KindToKeyword(expected[i]));
    }
    if (i == expected.size() - 1) absl::StrAppend(&unexpected_token_str, ".");
  }
  return error << unexpected_token_str;
}

// -- Actual parsing -----------------------------------------------------------

// Tries to parse a token of the given kind and fails if it sees anything else.
absl::StatusOr<Token> ExpectTokenKind(Token::Kind kind, TokenStream* tokens) {
  Token token = tokens->Next();
  if (token.kind != kind) return Unexpected(token, {kind}, tokens->source());
  return {token};
}

// Parses a constraint containing only binary Boolean operators at or above the
// given precedence. Operators below the given precedence are treated like EOF.
//
// The parser recognizes the following left-recursive grammar:
//
//   constraint ::=
//     | 'true'
//     | 'false'
//     | NUMERAL
//     | ID '(' STRING ')'
//     | ID ('.' ID)*         // key
//     | '::' ID              // attribute_access
//     | '!' constraint
//     | '-' constraint
//     | '(' constraint ')'
//     | constraint '::' ID
//     | constraint ('&&' | '||' | '->' | ';') constraint
//     | constraint ('==' | '!=' | '>' | '>=' | '<' | '<=') constraint
//
// As usual (see https://en.wikipedia.org/wiki/Left_recursion), we accomplish
// this by removing left recursion from the grammar by rewriting it as follows:
//
//   constraint ::= initial extension?
//
//   initial ::=
//     | 'true'
//     | 'false'
//     | NUMERAL
//     | ID '(' STRING ')'
//     | ID ('.' ID)*         // key
//     | '::' ID              // attribute_access
//     | '!' constraint
//     | '-' constraint
//     | '(' constraint ')'
//
//   extension ::=
//     | '::' ID extension
//     | ('&&' | '||' | '->'| ';') constraint extension
//     | ('==' | '!=' | '>' | '>=' | '<' | '<=') constraint
//
// extension is then right-recursive and can be implemented using a while loop.
absl::StatusOr<Expression> ParseConstraintAbove(ConstraintKind constraint_kind,
                                                TokenStream* tokens,
                                                int context_precedence) {
  // Try to parse an 'initial' AST.
  Expression ast;
  const Token token = tokens->Next();
  switch (token.kind) {
    case Token::TRUE:
    case Token::FALSE: {
      ASSIGN_OR_RETURN(ast, ast::MakeBooleanConstant(token));
      break;
    }
    case Token::BINARY:
    case Token::OCTARY:
    case Token::DECIMAL:
    case Token::HEXADEC: {
      ASSIGN_OR_RETURN(ast, ast::MakeIntegerConstant(token));
      break;
    }
    case Token::ID: {
      // Parse Network Addresses: ID '(' STRING ')'.
      if (tokens->Peek().kind == Token::LPAR) {
        tokens->Next();  // Discard the LPAR token.
        ASSIGN_OR_RETURN(Token string_token,
                         ExpectTokenKind(Token::STRING, tokens));
        ASSIGN_OR_RETURN(Token rpar_token,
                         ExpectTokenKind(Token::RPAR, tokens));
        ASSIGN_OR_RETURN(
            ast, ast::MakeNetworkAddressIntegerConstant(
                     token.text, string_token.text, token.start_location,
                     rpar_token.end_location));
      } else {
        // Parse variable: ID (DOT ID)*
        std::vector<Token> id_tokens = {token};
        while (tokens->Peek().kind == Token::DOT) {
          tokens->Next();  // discard Token::DOT
          ASSIGN_OR_RETURN(Token token, ExpectTokenKind(Token::ID, tokens));
          id_tokens.push_back(token);
        }
        ASSIGN_OR_RETURN(ast, ast::MakeVariable(id_tokens, constraint_kind));
      }
      break;
    }
    case Token::DOUBLE_COLON: {
      ASSIGN_OR_RETURN(const Token attribute_name,
                       ExpectTokenKind(Token::ID, tokens));
      ASSIGN_OR_RETURN(ast, ast::MakeAttributeAccess(token, attribute_name));
      break;
    }
    case Token::BANG: {
      ASSIGN_OR_RETURN(ast, ParseConstraintAbove(constraint_kind, tokens,
                                                 TokenPrecedence(token.kind)));
      ASSIGN_OR_RETURN(ast, ast::MakeBooleanNegation(token, std::move(ast)));
      break;
    }
    case Token::MINUS: {
      ASSIGN_OR_RETURN(ast, ParseConstraintAbove(constraint_kind, tokens,
                                                 TokenPrecedence(token.kind)));
      ASSIGN_OR_RETURN(ast, ast::MakeArithmeticNegation(token, std::move(ast)));
      break;
    }
    case Token::LPAR: {
      ASSIGN_OR_RETURN(ast, ParseConstraintAbove(constraint_kind, tokens, 0));
      RETURN_IF_ERROR(ExpectTokenKind(Token::RPAR, tokens).status());
      break;
    }
    default:
      return Unexpected(
          token,
          {Token::TRUE, Token::FALSE, Token::BINARY, Token::OCTARY,
           Token::DECIMAL, Token::HEXADEC, Token::ID, Token::DOUBLE_COLON,
           Token::BANG, Token::MINUS, Token::LPAR},
          tokens->source());
  }

  // Try to extend the AST, i.e. parse an 'extension'.
  while (true) {
    Token token = tokens->Peek();
    switch (token.kind) {
      case Token::END_OF_INPUT:
      case Token::RPAR:
        return ast;
      case Token::DOUBLE_COLON:
      case Token::AND:
      case Token::SEMICOLON:
      case Token::OR:
      case Token::IMPLIES:
      case Token::EQ:
      case Token::NE:
      case Token::GT:
      case Token::GE:
      case Token::LT:
      case Token::LE:
        if (context_precedence == TokenPrecedence(token.kind) &&
            TokenAssociativity(token.kind) == Associativity::NONE) {
          return ParseError(token, tokens->source())
                 << "operator " << token.kind
                 << " is non-associative; enclose expression to the left of "
                    "the operator in '(' and ')' to disambiguate?";
        }
        if (context_precedence > TokenPrecedence(token.kind) ||
            (context_precedence == TokenPrecedence(token.kind) &&
             TokenAssociativity(token.kind) == Associativity::LEFT)) {
          // Let the enclosing context parse this extension; it has higher
          // precedence.
          return ast;
        }
        // Commit to parsing this token and extension; done in a second.
        tokens->Next();
        break;
      default:
        return Unexpected(
            token,
            {Token::END_OF_INPUT, Token::RPAR, Token::DOUBLE_COLON, Token::AND,
             Token::SEMICOLON, Token::OR, Token::IMPLIES, Token::EQ, Token::NE,
             Token::GT, Token::GE, Token::LT, Token::LE},
            tokens->source());
    }
    // If we get here, we should parse an 'extension'.
    DCHECK(context_precedence < TokenPrecedence(token.kind) ||
           (context_precedence == TokenPrecedence(token.kind) &&
            TokenAssociativity(token.kind) == Associativity::RIGHT));
    if (token.kind == Token::SEMICOLON &&
        (tokens->Peek().kind == Token::END_OF_INPUT ||
         tokens->Peek().kind == Token::RPAR)) {
      // Nothing else to parse here. We tolerate trailing semicolons.
      return ast;
    }
    if (token.kind == Token::DOUBLE_COLON) {
      ASSIGN_OR_RETURN(Token field, ExpectTokenKind(Token::ID, tokens));
      ASSIGN_OR_RETURN(ast, ast::MakeFieldAccess(std::move(ast), field));
    } else {
      // token.kind is one of &&, ;, ||, ->, ==, !=, >, >=, <, <=.
      ASSIGN_OR_RETURN(Expression another_ast,
                       ParseConstraintAbove(constraint_kind, tokens,
                                            TokenPrecedence(token.kind)));
      ASSIGN_OR_RETURN(ast, ast::MakeBinaryExpression(token, std::move(ast),
                                                      std::move(another_ast)));
    }
  }
}

}  // namespace

// Parses `tokens` as expression, assuming that the `tokens` were lexed from the
// given `source`. The behavior of this function is undefined if this assumption
// is violated. Due to this tricky contract, we don't expose this function
// publicly.
absl::StatusOr<Expression> internal_parser::ParseConstraint(
    ConstraintKind constraint_kind, const std::vector<Token>& tokens,
    const ConstraintSource& source) {
  TokenStream token_stream(tokens, source);
  ASSIGN_OR_RETURN(Expression ast,
                   ParseConstraintAbove(constraint_kind, &token_stream, 0));
  RETURN_IF_ERROR(ExpectTokenKind(Token::END_OF_INPUT, &token_stream).status());
  return ast;
}

// -- Public interface ---------------------------------------------------------

// Public-facing version of `internal_parser::ParseConstraint` that provides a
// fool-proof & more-convenient API that combines lexing and parsing.
absl::StatusOr<Expression> ParseConstraint(ConstraintKind constraint_kind,
                                           const ConstraintSource& source) {
  const std::vector<Token> tokens = Tokenize(source);
  return internal_parser::ParseConstraint(constraint_kind, tokens, source);
}

}  // namespace p4_constraints
