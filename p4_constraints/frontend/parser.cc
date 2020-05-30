// Copyright 2020 The P4-Constraints Authors
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
#include <vector>

#include "absl/status/status.h"
#include "glog/logging.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/frontend/ast_constructors.h"
#include "p4_constraints/frontend/token.h"
#include "p4_constraints/quote.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace p4_constraints {

namespace {  // internal only

using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::SourceLocation;

// -- Infinite token stream ----------------------------------------------------

// For the purposes of parsing, it is convenient to model the input as an
// infinite stream of tokens (ending in infinitely many END_OF_INPUT tokens).
class TokenStream {
 public:
  explicit TokenStream(const std::vector<Token>& tokens) : tokens_{tokens} {};
  // Returns next token in stream.
  Token Peek() const;
  // Consumes and returns next token in stream, advancing the stream by 1.
  Token Next();

 private:
  const std::vector<Token>& tokens_;
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
    case Token::IMPLIES:
      return Associativity::RIGHT;
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
      LOG(DFATAL) << "Precedence for token " << kind
                  << "undeclared. Assuming 0.";
      return 0;
  }
}

// -- Error handling -----------------------------------------------------------

util::StatusBuilder ParseError(const SourceLocation& start,
                               const SourceLocation& end) {
  return util::InvalidArgumentErrorBuilder(UTIL_LOC)
         << QuoteSourceLocation(start, end) << "Parse error: ";
}

util::StatusBuilder ParseError(Token token) {
  return ParseError(token.start_location, token.end_location);
}

// Returns an error status indicating that the given token came as a surprise,
// since one of the given other tokens was expected.
absl::Status Unexpected(Token token, const std::vector<Token::Kind>& expected) {
  util::StatusBuilder error = ParseError(token);
  if (token.kind == Token::UNEXPECTED_CHAR) {
    // Slightly awkward phrasing because the unexpected character may actually
    // be further back in the input, see "known limitation" in lexer.h.
    return error << "unexpected character at or after '" << token.text << "'.";
  }

  error << "unexpected token: " << token.kind << ".";
  for (int i = 0; i < expected.size(); i++) {
    if (i == 0) {
      error << " Expected " << expected[i];
    } else if (i == expected.size() - 1) {
      error << ", or " << expected[i];
    } else {
      error << ", " << expected[i];
    }
    if (i == expected.size() - 1) error << ".";
  }
  return error;
}

// -- Actual parsing -----------------------------------------------------------

// Tries to parse a token of the given kind and fails if it sees anything else.
util::StatusOr<Token> ExpectTokenKind(Token::Kind kind, TokenStream* tokens) {
  Token token = tokens->Next();
  if (token.kind != kind) return Unexpected(token, {kind});
  return {token};
}

// Parses a constraint containing only binary Boolean operators at or above the
// given precedence. Operators below the given precedence are treated like EOF.
//
// The parser recognizes the following left-recursive grammar:
//
//   constraint ::=
//     | 'true' | 'false'
//     |  <numeral> | <key>
//     | '!' constraint
//     | '-' constraint
//     | '(' constraint ')'
//     | constraint '::' <id>
//     | constraint ('&&' | '||' | '->' | ';') constraint
//     | constraint ('==' | '!=' | '>' | '>=' | '<' | '<=') constraint
//
//   <key> ::= <id> ('.' <id>)*
//
// As usual (see https://en.wikipedia.org/wiki/Left_recursion), we accomplish
// this by removing left recursion from the grammar by rewriting it as follows:
//
//   constraint ::= initial extension?
//
//   initial ::=
//     | 'true' | 'false'
//     | <numeral> | <key>
//     | '!' constraint
//     | '-' constraint
//     | '(' constraint ')'
//
//   extension ::=
//     | '::' <id> extension
//     | ('&&' | '||' | '->'| ';') constraint extension
//     | ('==' | '!=' | '>' | '>=' | '<' | '<=') constraint
//
// extension is then right-recursive and can be implemented using a while loop.
util::StatusOr<Expression> ParseConstraintAbove(int context_precedence,
                                                TokenStream* tokens) {
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
      // Parse key: ID (DOT ID)*
      std::vector<Token> key_fragments = {token};
      while (tokens->Peek().kind == Token::DOT) {
        tokens->Next();  // discard Token::DOT
        ASSIGN_OR_RETURN(Token token, ExpectTokenKind(Token::ID, tokens));
        key_fragments.push_back(token);
      }
      ASSIGN_OR_RETURN(ast, ast::MakeKey(key_fragments));
      break;
    }
    case Token::BANG: {
      ASSIGN_OR_RETURN(
          ast, ParseConstraintAbove(TokenPrecedence(token.kind), tokens));
      ASSIGN_OR_RETURN(ast, ast::MakeBooleanNegation(token, ast));
      break;
    }
    case Token::MINUS: {
      ASSIGN_OR_RETURN(
          ast, ParseConstraintAbove(TokenPrecedence(token.kind), tokens));
      ASSIGN_OR_RETURN(ast, ast::MakeArithmeticNegation(token, ast));
      break;
    }
    case Token::LPAR: {
      ASSIGN_OR_RETURN(ast, ParseConstraintAbove(0, tokens));
      RETURN_IF_ERROR(ExpectTokenKind(Token::RPAR, tokens).status());
      break;
    }
    default:
      return Unexpected(
          token, {Token::TRUE, Token::FALSE, Token::BINARY, Token::OCTARY,
                  Token::DECIMAL, Token::HEXADEC, Token::ID, Token::BANG,
                  Token::MINUS, Token::LPAR});
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
          return ParseError(token)
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
             Token::GT, Token::GE, Token::LT, Token::LE});
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
      ASSIGN_OR_RETURN(ast, ast::MakeFieldAccess(ast, field));
    } else {
      // token.kind is one of &&, ;, ||, ->, ==, !=, >, >=, <, <=.
      ASSIGN_OR_RETURN(
          Expression another_ast,
          ParseConstraintAbove(TokenPrecedence(token.kind), tokens));
      ASSIGN_OR_RETURN(ast, ast::MakeBinaryExpression(token, ast, another_ast));
    }
  }
}

}  // namespace

// -- Public interface ---------------------------------------------------------

util::StatusOr<Expression> ParseConstraint(const std::vector<Token>& tokens) {
  TokenStream token_stream(tokens);
  ASSIGN_OR_RETURN(Expression ast, ParseConstraintAbove(0, &token_stream));
  RETURN_IF_ERROR(ExpectTokenKind(Token::END_OF_INPUT, &token_stream).status());
  return ast;
}

}  // namespace p4_constraints
