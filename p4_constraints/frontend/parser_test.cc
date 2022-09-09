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

#include "absl/status/statusor.h"
#include "gutils/protocol_buffer_matchers.h"
#include "gutils/status_matchers.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/frontend/token.h"

namespace p4_constraints {

using ::gutils::testing::EqualsProto;
using ::gutils::testing::proto::Partially;
using ::gutils::testing::status::IsOkAndHolds;

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
  const Token kDoubleColon = DummyToken(Token::DOUBLE_COLON);
  const Token kEndOfFile = DummyToken(Token::END_OF_INPUT);
  const Token kUnexpectedChar = DummyToken(Token::UNEXPECTED_CHAR);

  // Used for valid input. Not important for the purpose of unit testing.
  const ConstraintSource kDummySource{
      .constraint_string = " ",
      .constraint_location = ast::SourceLocation(),
  };
};

TEST_F(ParserTest, Positive) {
  const std::pair<std::vector<Token>, std::string> tests[] =
      {
          // Boolean constants.
          {{kTrue}, "boolean_constant: true"},
          {{kFalse}, "boolean_constant: false"},

          // Tests, comparison operators, numerals.
          {{kId, kEq, Binary("11")}, R"pb(binary_expression: {
                                            left: { key: "" },
                                            binop: EQ,
                                            right: { integer_constant: "3" }
                                          })pb"},
          {{kId, kNe, Octary("11")}, R"pb(binary_expression: {
                                            left: { key: "" },
                                            binop: NE,
                                            right: { integer_constant: "9" }
                                          })pb"},
          {{kId, kGt, Decimal("11")}, R"pb(binary_expression: {
                                             left: { key: "" },
                                             binop: GT,
                                             right: { integer_constant: "11" }
                                           })pb"},
          {{kId, kGe, Hexadec("11")}, R"pb(binary_expression: {
                                             left: { key: "" },
                                             binop: GE,
                                             right: { integer_constant: "17" }
                                           })pb"},
          {{kId, kLt, Hexadec("1f")}, R"pb(binary_expression: {
                                             left: { key: "" },
                                             binop: LT,
                                             right: { integer_constant: "31" }
                                           })pb"},
          {{kId, kLe, Hexadec("af")},
           R"pb(binary_expression: {
                  left: { key: "" },
                  binop: LE,
                  right: { integer_constant: "175" }
                })pb"},

          // Boolean negation.
          {{kNot, kTrue}, R"(boolean_negation: {boolean_constant: true})"},
          {{kNot, kFalse}, R"(boolean_negation: {boolean_constant: false})"},
          {{kNot, kLpar, kId, kEq, Decimal("000123"), kRpar},
           R"pb(boolean_negation: {
                  binary_expression: {
                    left: { key: "" },
                    binop: EQ,
                    right: { integer_constant: "123" }
                  }
                })pb"},
          {{kNot, kNot, kTrue},
           R"pb(boolean_negation: {
                  boolean_negation: { boolean_constant: true }
                })pb"},

          // Binary Boolean operators.
          {{kTrue, kAnd, kTrue}, R"pb(binary_expression: {
                                        left: { boolean_constant: true },
                                        binop: AND,
                                        right: { boolean_constant: true }
                                      })pb"},
          {{kTrue, kOr, kTrue}, R"pb(binary_expression: {
                                       left: { boolean_constant: true },
                                       binop: OR,
                                       right: { boolean_constant: true }
                                     })pb"},
          {{kTrue, kImplies, kTrue}, R"pb(binary_expression: {
                                            left: { boolean_constant: true },
                                            binop: IMPLIES,
                                            right: { boolean_constant: true }
                                          })pb"},

          // Associativity.
          {{kTrue, kAnd, kTrue, kAnd, kTrue},
           R"pb(binary_expression: {
                  left: {
                    binary_expression: {
                      left: { boolean_constant: true },
                      binop: AND,
                      right: { boolean_constant: true }
                    }
                  },
                  binop: AND,
                  right: { boolean_constant: true }
                })pb"},
          {{kTrue, kAnd, kLpar, kTrue, kAnd, kTrue, kRpar},
           R"pb(binary_expression: {
                  left: { boolean_constant: true },
                  binop: AND,
                  right: {
                    binary_expression: {
                      left: { boolean_constant: true },
                      binop: AND,
                      right: { boolean_constant: true }
                    }
                  }
                })pb"},
          {{kTrue, kOr, kTrue, kOr, kTrue},
           R"pb(binary_expression: {
                  left: {
                    binary_expression: {
                      left: { boolean_constant: true },
                      binop: OR,
                      right: { boolean_constant: true }
                    }
                  },
                  binop: OR,
                  right: { boolean_constant: true }
                })pb"},
          {{kTrue, kOr, kLpar, kTrue, kOr, kTrue, kRpar},
           R"pb(binary_expression: {
                  left: { boolean_constant: true },
                  binop: OR,
                  right: {
                    binary_expression: {
                      left: { boolean_constant: true },
                      binop: OR,
                      right: { boolean_constant: true }
                    }
                  }
                })pb"},

          // Precedence.
          {{kNot, kTrue, kAnd, kTrue, kOr, kTrue, kImplies, kTrue},
           R"pb(binary_expression: {
                  binop: IMPLIES,
                  left: {
                    binary_expression: {
                      binop: OR,
                      left: {
                        binary_expression: {
                          binop: AND,
                          left: {
                            boolean_negation: { boolean_constant: true }
                          },
                          right: { boolean_constant: true },
                        }
                      },
                      right: { boolean_constant: true },
                    }
                  }
                })pb"},
          {{kNot, kTrue, kImplies, kTrue, kOr, kTrue, kAnd, kTrue},
           R"pb(binary_expression: {
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
                })pb"},

          // Parenthesis.
          {{kLpar, kTrue, kRpar}, "boolean_constant: true"},
          {{kLpar, kLpar, kTrue, kRpar, kRpar}, "boolean_constant: true"},
          {{kLpar, kLpar, kLpar, kTrue, kRpar, kRpar, kRpar},
           "boolean_constant: true"},

          // Metadata access.
          {{kDoubleColon, kId}, R"pb(metadata_access { metadata_name: "" })pb"},
      };

  for (const auto& test : tests) {
    const auto& tokens = test.first;
    const auto& expected_str = test.second;

    EXPECT_THAT(internal_parser::ParseConstraint(tokens, kDummySource),
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
    auto result = internal_parser::ParseConstraint(tokens, kDummySource);
    if (result.ok()) {
      FAIL() << "Expected parsing to fail, but parsed "
             << result.value().DebugString();
    }
  }
}

}  // namespace p4_constraints
