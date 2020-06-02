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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "p4_constraints/ast.pb.h"
#include "p4_constraints/frontend/token.h"
#include "util/protocol_buffer_matchers.h"
#include "util/status_matchers.h"
#include "util/statusor.h"

namespace p4_constraints {

using ::util::testing::EqualsProto;
using ::util::testing::proto::Partially;
using ::util::testing::status::IsOkAndHolds;

Token Binary(std::string text) {
  return Token(Token::BINARY, text, ast::SourceLocation(),
               ast::SourceLocation());
}

Token Octary(std::string text) {
  return Token(Token::Kind::OCTARY, text, ast::SourceLocation(),
               ast::SourceLocation());
}

Token Decimal(std::string text) {
  return Token(Token::Kind::DECIMAL, text, ast::SourceLocation(),
               ast::SourceLocation());
}

Token Hexadec(std::string text) {
  return Token(Token::Kind::HEXADEC, text, ast::SourceLocation(),
               ast::SourceLocation());
}

Token DummyToken(Token::Kind kind) {
  return Token(kind, "", ast::SourceLocation(), ast::SourceLocation());
}

struct ParserTest : public ::testing::Test {
  const Token kTrue = DummyToken(Token::TRUE);
  const Token kFalse = DummyToken(Token::FALSE);
  const Token kNot = DummyToken(Token::BANG);
  const Token kAnd = DummyToken(Token::AND);
  const Token kOr = DummyToken(Token::OR);
  const Token kImplies = DummyToken(Token::IMPLIES);
  const Token kEq = DummyToken(Token::EQ);
  const Token kNe = DummyToken(Token::NE);
  const Token kGt = DummyToken(Token::GT);
  const Token kGe = DummyToken(Token::GE);
  const Token kLt = DummyToken(Token::LT);
  const Token kLe = DummyToken(Token::LE);
  const Token kLpar = DummyToken(Token::LPAR);
  const Token kRpar = DummyToken(Token::RPAR);
  const Token kId = DummyToken(Token::ID);
  const Token kEndOfFile = DummyToken(Token::END_OF_INPUT);
  const Token kUnexpectedChar = DummyToken(Token::UNEXPECTED_CHAR);
};

TEST_F(ParserTest, Positive) {
  const std::pair<std::vector<Token>, std::string> tests[] = {
      // Boolean constants.
      {{kTrue}, "boolean_constant: true"},
      {{kFalse}, "boolean_constant: false"},

      // Tests, comparison operators, numerals.
      {{kId, kEq, Binary("11")}, R"PROTO(binary_expression: {
                                           left: { key: "" },
                                           binop: EQ,
                                           right: { integer_constant: "3" }
                                         })PROTO"},
      {{kId, kNe, Octary("11")}, R"PROTO(binary_expression: {
                                           left: { key: "" },
                                           binop: NE,
                                           right: { integer_constant: "9" }
                                         })PROTO"},
      {{kId, kGt, Decimal("11")}, R"PROTO(binary_expression: {
                                            left: { key: "" },
                                            binop: GT,
                                            right: { integer_constant: "11" }
                                          })PROTO"},
      {{kId, kGe, Hexadec("11")}, R"PROTO(binary_expression: {
                                            left: { key: "" },
                                            binop: GE,
                                            right: { integer_constant: "17" }
                                          })PROTO"},
      {{kId, kLt, Hexadec("1f")}, R"PROTO(binary_expression: {
                                            left: { key: "" },
                                            binop: LT,
                                            right: { integer_constant: "31" }
                                          })PROTO"},
      {{kId, kLe, Hexadec("af")},
       R"PROTO(binary_expression: {
                 left: { key: "" },
                 binop: LE,
                 right: { integer_constant: "175" }
               })PROTO"},

      // Boolean negation.
      {{kNot, kTrue}, R"(boolean_negation: {boolean_constant: true})"},
      {{kNot, kFalse}, R"(boolean_negation: {boolean_constant: false})"},
      {{kNot, kLpar, kId, kEq, Decimal("000123"), kRpar},
       R"PROTO(boolean_negation: {
                 binary_expression: {
                   left: { key: "" },
                   binop: EQ,
                   right: { integer_constant: "123" }
                 }
               })PROTO"},
      {{kNot, kNot, kTrue},
       R"PROTO(boolean_negation: {
                 boolean_negation: { boolean_constant: true }
               })PROTO"},

      // Binary Boolean operators.
      {{kTrue, kAnd, kTrue}, R"PROTO(binary_expression: {
                                       left: { boolean_constant: true },
                                       binop: AND,
                                       right: { boolean_constant: true }
                                     })PROTO"},
      {{kTrue, kOr, kTrue}, R"PROTO(binary_expression: {
                                      left: { boolean_constant: true },
                                      binop: OR,
                                      right: { boolean_constant: true }
                                    })PROTO"},
      {{kTrue, kImplies, kTrue}, R"PROTO(binary_expression: {
                                           left: { boolean_constant: true },
                                           binop: IMPLIES,
                                           right: { boolean_constant: true }
                                         })PROTO"},

      // Associativity.
      {{kTrue, kAnd, kTrue, kAnd, kTrue},
       R"PROTO(binary_expression: {
                 left: {
                   binary_expression: {
                     left: { boolean_constant: true },
                     binop: AND,
                     right: { boolean_constant: true }
                   }
                 },
                 binop: AND,
                 right: { boolean_constant: true }
               })PROTO"},
      {{kTrue, kAnd, kLpar, kTrue, kAnd, kTrue, kRpar},
       R"PROTO(binary_expression: {
                 left: { boolean_constant: true },
                 binop: AND,
                 right: {
                   binary_expression: {
                     left: { boolean_constant: true },
                     binop: AND,
                     right: { boolean_constant: true }
                   }
                 }
               })PROTO"},
      {{kTrue, kOr, kTrue, kOr, kTrue},
       R"PROTO(binary_expression: {
                 left: {
                   binary_expression: {
                     left: { boolean_constant: true },
                     binop: OR,
                     right: { boolean_constant: true }
                   }
                 },
                 binop: OR,
                 right: { boolean_constant: true }
               })PROTO"},
      {{kTrue, kOr, kLpar, kTrue, kOr, kTrue, kRpar},
       R"PROTO(binary_expression: {
                 left: { boolean_constant: true },
                 binop: OR,
                 right: {
                   binary_expression: {
                     left: { boolean_constant: true },
                     binop: OR,
                     right: { boolean_constant: true }
                   }
                 }
               })PROTO"},

      // Precedence.
      {{kNot, kTrue, kAnd, kTrue, kOr, kTrue, kImplies, kTrue},
       R"PROTO(binary_expression: {
                 binop: IMPLIES,
                 left: {
                   binary_expression: {
                     binop: OR,
                     left: {
                       binary_expression: {
                         binop: AND,
                         left: { boolean_negation: { boolean_constant: true } },
                         right: { boolean_constant: true },
                       }
                     },
                     right: { boolean_constant: true },
                   }
                 }
               })PROTO"},
      {{kNot, kTrue, kImplies, kTrue, kOr, kTrue, kAnd, kTrue},
       R"PROTO(binary_expression: {
                 binop: IMPLIES,
                 left: { boolean_negation: { boolean_constant: true } },
                 right: {
                   binary_expression: {
                     binop: OR,
                     left: { boolean_constant: true },
                     right: {
                       binary_expression: {
                         binop: AND,
                         left: { boolean_constant: true },
                         right: { boolean_constant: true },
                       }
                     }
                   }
                 }
               })PROTO"},

      // Parenthesis.
      {{kLpar, kTrue, kRpar}, "boolean_constant: true"},
      {{kLpar, kLpar, kTrue, kRpar, kRpar}, "boolean_constant: true"},
      {{kLpar, kLpar, kLpar, kTrue, kRpar, kRpar, kRpar},
       "boolean_constant: true"},
  };

  for (const auto& test : tests) {
    const auto& tokens = test.first;
    const auto& expected_str = test.second;

    EXPECT_THAT(ParseConstraint(tokens),
                IsOkAndHolds(Partially(EqualsProto(expected_str))));
  }
}

TEST_F(ParserTest, Negative) {
  const std::vector<Token> tests[] = {
      // Boolean constants.
      {kTrue, kFalse},

      // Boolean negation.
      {kNot},
      {kTrue, kNot},
      {kTrue, kNot, kTrue},

      // Binary Boolean operators.
      {kTrue, kAnd},
      {kAnd, kTrue, kTrue},

      // Parenthesis.
      {kLpar, kTrue},
      {kLpar, kTrue, kRpar, kRpar},
      {kLpar, kLpar, kTrue, kRpar},
      {kRpar, kTrue},
      {kRpar, kTrue, kRpar},
      {kRpar, kTrue, kLpar},

      // Non-associative operators
      {kTrue, kImplies, kTrue, kImplies, kTrue},
      {kTrue, kEq, kTrue, kNe, kTrue},
      {kTrue, kNe, kTrue, kGt, kTrue},
      {kTrue, kGt, kTrue, kGe, kTrue},
      {kTrue, kGe, kTrue, kLt, kTrue},
      {kTrue, kLt, kTrue, kLe, kTrue},
  };

  for (auto& tokens : tests) {
    auto result = ParseConstraint(tokens);
    if (result.ok()) {
      FAIL() << "Expected parsing to fail, but parsed "
             << result.ValueOrDie().DebugString();
    }
  }
}

}  // namespace p4_constraints
