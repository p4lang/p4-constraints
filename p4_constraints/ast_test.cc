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

#include "p4_constraints/ast.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/substitute.h"
#include "gutils/parse_text_proto.h"
#include "gutils/status_matchers.h"

namespace p4_constraints {
namespace ast {

using ::gutils::testing::status::IsOkAndHolds;
using ::testing::Contains;
using ::testing::Eq;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

Expression ParseRawAst(const std::string constraint) {
  return gutils::ParseTextProtoOrDie<Expression>(constraint);
}

TEST(SizeTest, SizeOfBooleanConstantsOneAndNotCached) {
  Expression const_true = ParseRawAst("boolean_constant: true");
  SizeCache size_cache;
  EXPECT_THAT(Size(const_true, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));

  Expression const_false = ParseRawAst("boolean_constant: false");
  size_cache.clear();
  EXPECT_THAT(Size(const_false, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));
}

TEST(SizeTest, SizeOfIntegerConstantOneAndNotCached) {
  for (auto int_str :
       {"0", "-1", "1", "42", "-9042852073498123679518173785123857"}) {
    Expression expr =
        ParseRawAst(absl::Substitute(R"(integer_constant: "$0")", int_str));
    SizeCache size_cache;
    EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(1));
    EXPECT_THAT(size_cache.size(), Eq(0));
  }
}

TEST(SizeTest, SizeOfFieldAccessOneAndNotCached) {
  // "A::B"
  Expression expr1 = ParseRawAst(R"pb(
    field_access {
      field: "B"
      expr { key: "A" }
    })pb");
  SizeCache size_cache;
  EXPECT_THAT(Size(expr1, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));

  // "A::B::C::D"
  Expression expr2 = ParseRawAst(R"pb(field_access {
                                        field: "D"
                                        expr {
                                          field_access {
                                            field: "C"
                                            expr {
                                              field_access {
                                                field: "B"
                                                expr { key: "A" }
                                              }
                                            }
                                          }
                                        }
                                      })pb");
  size_cache.clear();
  EXPECT_THAT(Size(expr2, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));
}

TEST(SizeTest, SizeOfAttrAccessOneAndNotCached) {
  // ::priority
  Expression expr =
      ParseRawAst(R"pb(attribute_access { attribute_name: "priority" })pb");
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));
}

TEST(SizeTest, SizeOfArithmeticNegationOneAndNotCached) {
  Expression inner_expr = ParseRawAst(R"(integer_constant: "42")");
  // -42 ... ----42
  for (int i = 0; i < 4; i++) {
    Expression expr = Expression();
    *expr.mutable_arithmetic_negation() = inner_expr;
    SizeCache size_cache;
    EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(1));
    EXPECT_THAT(size_cache.size(), Eq(0));
    inner_expr = expr;
  }
}

TEST(SizeTest, SizeOfBooleanNegationAddsOneAndCached) {
  Expression inner_expr = ParseRawAst("boolean_constant: true");
  // !true ... !!!!true
  for (int i = 0; i < 4; i++) {
    Expression expr = Expression();
    *expr.mutable_boolean_negation() = inner_expr;
    SizeCache size_cache;
    EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(Eq(i + 2)));
    EXPECT_THAT(size_cache.size(), Eq(i + 1));
    const auto* subexpr = &expr;
    for (int j = 0; j < i + 1; j++) {
      EXPECT_THAT(size_cache, Contains(Pair(subexpr, i + 2 - j)));
      if (j == i) break;
      subexpr = &(subexpr->boolean_negation());
    }
    inner_expr = expr;
  }
}

TEST(SizeTest, SizeOfBinaryBooleanExpressionAddsOneAndCached) {
  // true && false
  Expression expr = ParseRawAst(R"pb(
    binary_expression {
      binop: AND
      left { boolean_constant: true }
      right { boolean_constant: false }
    })pb");
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(Eq(3)));
  EXPECT_THAT(size_cache, UnorderedElementsAre(Pair(&expr, 3)));
}

TEST(SizeTest, SizeOfBinaryNonBooleanExpressionAddsOneAndCached) {
  // ether_type != 0x0800
  Expression expr = ParseRawAst(R"pb(binary_expression {
                                       binop: NE
                                       left { key: "ether_type" }
                                       right { integer_constant: "2048" }
                                     })pb");
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(Eq(3)));
  EXPECT_THAT(size_cache, UnorderedElementsAre(Pair(&expr, 3)));
}

TEST(SizeTest, SizeOfConstraint1SevenAndCached) {
  // ether_type != 0x0800 && ether_type != 0x86dd;
  Expression expr = ParseRawAst(R"pb(binary_expression {
                                       binop: AND
                                       left {
                                         binary_expression {
                                           binop: NE
                                           left { key: "ether_type" }
                                           right { integer_constant: "2048" }
                                         }
                                       }
                                       right {
                                         binary_expression {
                                           binop: NE
                                           left { key: "ether_type" }
                                           right { integer_constant: "34525" }
                                         }
                                       }
                                     })pb");
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(Eq(7)));
  EXPECT_THAT(size_cache,
              UnorderedElementsAre(Pair(&expr, 7),
                                   Pair(&expr.binary_expression().left(), 3),
                                   Pair(&expr.binary_expression().right(), 3)));
}

TEST(SizeTest, SizeOfConstraint2FifthteenAndCached) {
  // ttl::mask != 0 -> (is_ip == 1 || is_ipv4 == 1 || is_ipv6 == 1);
  Expression expr = ParseRawAst(
      R"pb(binary_expression {
             binop: IMPLIES
             left {
               binary_expression {
                 binop: NE
                 left {
                   field_access {
                     field: "mask"
                     expr { key: "ttl" }
                   }
                 }
                 right { integer_constant: "0" }
               }
             }
             right {
               binary_expression {
                 binop: OR
                 left {
                   binary_expression {
                     binop: OR
                     left {
                       binary_expression {
                         binop: EQ
                         left { key: "is_ip" }
                         right { integer_constant: "1" }
                       }
                     }
                     right {
                       binary_expression {
                         binop: EQ
                         left { key: "is_ipv4" }
                         right { integer_constant: "1" }
                       }
                     }
                   }
                 }
                 right {
                   binary_expression {
                     binop: EQ
                     left { key: "is_ipv6" }
                     right { integer_constant: "1" }
                   }
                 }
               }
             }
           })pb");
  auto* or_subexpr = &expr.binary_expression().right();
  auto* or_subsubexpr = &or_subexpr->binary_expression().left();
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(Eq(15)));
  EXPECT_THAT(size_cache,
              UnorderedElementsAre(
                  Pair(&expr, 15), Pair(&expr.binary_expression().left(), 3),
                  Pair(&expr.binary_expression().right(), 11),
                  Pair(&or_subexpr->binary_expression().left(), 7),
                  Pair(&or_subexpr->binary_expression().right(), 3),
                  Pair(&or_subsubexpr->binary_expression().left(), 3),
                  Pair(&or_subsubexpr->binary_expression().right(), 3)));
}

TEST(SizeTest, CacheIsUsed) {
  // ether_type != 0x0800 && ether_type != 0x86dd;
  Expression expr = ParseRawAst(R"pb(binary_expression {
                                       binop: AND
                                       left {
                                         binary_expression {
                                           binop: NE
                                           left { key: "ether_type" }
                                           right { integer_constant: "2048" }
                                         }
                                       }
                                       right {
                                         binary_expression {
                                           binop: NE
                                           left { key: "ether_type" }
                                           right { integer_constant: "34525" }
                                         }
                                       }
                                     })pb");
  SizeCache size_cache;
  size_cache.insert({&expr, 343});
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(Eq(343)));
  EXPECT_THAT(size_cache.size(), Eq(1));
}

TEST(SizeTest, NoCacheOkay) {
  // ether_type != 0x0800 && ether_type != 0x86dd;
  Expression expr = ParseRawAst(R"pb(binary_expression {
                                       binop: AND
                                       left {
                                         binary_expression {
                                           binop: NE
                                           left { key: "ether_type" }
                                           right { integer_constant: "2048" }
                                         }
                                       }
                                       right {
                                         binary_expression {
                                           binop: NE
                                           left { key: "ether_type" }
                                           right { integer_constant: "34525" }
                                         }
                                       }
                                     })pb");
  EXPECT_THAT(Size(expr, nullptr), IsOkAndHolds(Eq(7)));
}

TEST(AddVariables, ReturnsEmptyForActionParameter) {
  Expression expr = ParseRawAst(R"pb(
    binary_expression {
      binop: GE
      left { action_parameter: "1" }
      right { action_parameter: "2" }
    }
  )pb");

  absl::flat_hash_set<std::string> expected = {"1", "2"};
  EXPECT_EQ(GetVariables(expr), expected);
}

}  // namespace ast
}  // namespace p4_constraints
