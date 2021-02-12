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

#include "p4_constraints/frontend/ast_constructors.h"

#include <gmpxx.h>

#include <sstream>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "gutils/ret_check.h"
#include "gutils/status_macros.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/frontend/token.h"

namespace p4_constraints {
namespace ast {

namespace {

// -- Auxiliary conversion functions -------------------------------------------

// Converts token.h to ast.proto representation.
absl::StatusOr<ast::BinaryOperator> ConvertBinaryOperator(Token::Kind binop) {
  switch (binop) {
    case Token::AND:
    case Token::SEMICOLON:
      return ast::AND;
    case Token::OR:
      return ast::OR;
    case Token::IMPLIES:
      return ast::IMPLIES;
    case Token::EQ:
      return ast::EQ;
    case Token::NE:
      return ast::NE;
    case Token::GT:
      return ast::GT;
    case Token::GE:
      return ast::GE;
    case Token::LT:
      return ast::LT;
    case Token::LE:
      return ast::LE;
    default:
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "expected binary operator, got " << binop;
  }
}

absl::StatusOr<std::string> ConvertNumeral(Token numeral_token) {
  mpz_class numeral;
  switch (numeral_token.kind) {
    case Token::BINARY:
      RET_CHECK_EQ(numeral.set_str(numeral_token.text, 2), 0)
          << "invalid binary string \"" << numeral_token.text << "\".\n";
      return numeral.get_str(10);
    case Token::OCTARY:
      RET_CHECK_EQ(numeral.set_str(numeral_token.text, 8), 0)
          << "invalid octary string \"" << numeral_token.text << "\".\n";
      return numeral.get_str(10);
    case Token::DECIMAL:
      RET_CHECK_EQ(numeral.set_str(numeral_token.text, 10), 0)
          << "invalid decimal string \"" << numeral_token.text << "\".\n";
      return numeral.get_str(10);
    case Token::HEXADEC:
      RET_CHECK_EQ(numeral.set_str(numeral_token.text, 16), 0)
          << "invalid hexadecimal string \"" << numeral_token.text << "\".\n";
      return numeral.get_str(10);
    default:
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "expected numeral, got " << numeral_token.kind;
  }
}

// -- Auxiliary base constructors ----------------------------------------------

ast::Expression LocatedExpression(const ast::SourceLocation& start_location,
                                  const ast::SourceLocation& end_location) {
  ast::Expression ast;
  *ast.mutable_start_location() = start_location;
  *ast.mutable_end_location() = end_location;
  return ast;
}

}  // namespace

// -- Public AST constructors --------------------------------------------------

absl::StatusOr<ast::Expression> MakeBooleanConstant(Token boolean) {
  RET_CHECK(boolean.kind == Token::TRUE || boolean.kind == Token::FALSE)
      << "expected boolean, got " << boolean.kind;
  ast::Expression ast =
      LocatedExpression(boolean.start_location, boolean.end_location);
  ast.set_boolean_constant(boolean.kind == Token::TRUE);
  return ast;
}

absl::StatusOr<ast::Expression> MakeIntegerConstant(Token numeral) {
  ASSIGN_OR_RETURN(std::string numeral_str, ConvertNumeral(numeral));
  ast::Expression ast =
      LocatedExpression(numeral.start_location, numeral.end_location);
  ast.set_integer_constant(numeral_str);
  return ast;
}

absl::StatusOr<ast::Expression> MakeBooleanNegation(Token bang_token,
                                                    ast::Expression operand) {
  RET_CHECK_EQ(bang_token.kind, Token::BANG);
  ast::Expression ast =
      LocatedExpression(bang_token.start_location, operand.end_location());
  *ast.mutable_boolean_negation() = std::move(operand);
  return ast;
}

absl::StatusOr<ast::Expression> MakeArithmeticNegation(
    Token minus_token, ast::Expression operand) {
  RET_CHECK_EQ(minus_token.kind, Token::MINUS);
  ast::Expression ast =
      LocatedExpression(minus_token.start_location, operand.end_location());
  *ast.mutable_arithmetic_negation() = std::move(operand);
  return ast;
}

absl::StatusOr<ast::Expression> MakeKey(absl::Span<const Token> key_fragments) {
  RET_CHECK_GT(key_fragments.size(), 0);
  ast::Expression ast = LocatedExpression(key_fragments.front().start_location,
                                          key_fragments.back().end_location);
  std::stringstream key{};
  for (int i = 0; i < key_fragments.size(); i++) {
    const Token& id = key_fragments[i];
    RET_CHECK_EQ(id.kind, Token::ID);
    key << (i == 0 ? "" : ".") << id.text;
  }
  ast.set_key(key.str());
  return ast;
}

absl::StatusOr<ast::Expression> MakeBinaryExpression(Token binop_token,
                                                     ast::Expression left,
                                                     ast::Expression right) {
  ast::Expression ast =
      LocatedExpression(left.start_location(), right.end_location());
  ast::BinaryExpression* binexpr = ast.mutable_binary_expression();

  ASSIGN_OR_RETURN(ast::BinaryOperator binop,
                   ConvertBinaryOperator(binop_token.kind));
  binexpr->set_binop(binop);
  *binexpr->mutable_left() = std::move(left);
  *binexpr->mutable_right() = std::move(right);
  return ast;
}

absl::StatusOr<ast::Expression> MakeFieldAccess(ast::Expression expr,
                                                Token field) {
  RET_CHECK_EQ(field.kind, Token::ID);
  ast::Expression ast =
      LocatedExpression(expr.start_location(), field.end_location);
  *ast.mutable_field_access()->mutable_expr() = std::move(expr);
  ast.mutable_field_access()->set_field(field.text);
  return ast;
}

}  // namespace ast
}  // namespace p4_constraints
