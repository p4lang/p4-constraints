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

#include "p4_constraints/ast.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gutils/status_macros.h"
#include "gutils/status_matchers.h"
#include "p4_constraints/frontend/lexer.h"
#include "p4_constraints/frontend/parser.h"

namespace p4_constraints {
namespace ast {

using ::gutils::testing::status::IsOkAndHolds;
using ::testing::Contains;
using ::testing::Eq;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

// TODO(verios): Consider using raw proto strings in these unit tests instead in
// order to decouple this unit from the lexer and parser
absl::StatusOr<Expression> StringToAST(absl::string_view constraint) {
  return ParseConstraint(Tokenize(constraint, ast::SourceLocation()));
}

TEST(SizeTest, SizeOfBooleanConstantsOneAndNotCached) {
  ASSERT_OK_AND_ASSIGN(
      Expression const_true,
      ParseConstraint(Tokenize("true", ast::SourceLocation())));
  SizeCache size_cache;
  EXPECT_THAT(Size(const_true, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));

  ASSERT_OK_AND_ASSIGN(
      Expression const_false,
      ParseConstraint(Tokenize("false", ast::SourceLocation())));
  size_cache.clear();
  EXPECT_THAT(Size(const_false, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));
}

TEST(SizeTest, SizeOfIntegerConstantOneAndNotCached) {
  for (auto int_str :
       {"0", "-1", "1", "42", "-9042852073498123679518173785123857"}) {
    ASSERT_OK_AND_ASSIGN(Expression expr, StringToAST(int_str));
    SizeCache size_cache;
    EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(1));
    EXPECT_THAT(size_cache.size(), Eq(0));
  }
}

TEST(SizeTest, SizeOfFieldAccessOneAndNotCached) {
  ASSERT_OK_AND_ASSIGN(Expression expr1, StringToAST("A::B"));
  SizeCache size_cache;
  EXPECT_THAT(Size(expr1, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));

  ASSERT_OK_AND_ASSIGN(Expression expr2, StringToAST("A::B::C::D"));
  size_cache.clear();
  EXPECT_THAT(Size(expr2, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));
}

TEST(SizeTest, SizeOfMetaAccessOneAndNotCached) {
  ASSERT_OK_AND_ASSIGN(Expression expr, StringToAST("::priority"));
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(1));
  EXPECT_THAT(size_cache.size(), Eq(0));
}

TEST(SizeTest, SizeOfArithmeticNegationOneAndNotCached) {
  std::string ast_string = "42";
  for (int i = 0; i < 4; i++) {
    ast_string = absl::StrCat("-", ast_string);
    ASSERT_OK_AND_ASSIGN(Expression expr, StringToAST(ast_string));
    SizeCache size_cache;
    EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(1));
    EXPECT_THAT(size_cache.size(), Eq(0));
  }
}

TEST(SizeTest, SizeOfBooleanNegationAddsOneAndCached) {
  std::string ast_string = "true";
  for (int i = 0; i < 4; i++) {
    ast_string = absl::StrCat("!", ast_string);
    ASSERT_OK_AND_ASSIGN(Expression expr, StringToAST(ast_string));
    SizeCache size_cache;
    EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(i + 2));
    EXPECT_THAT(size_cache.size(), Eq(i + 1));
    const auto* subexpr = &expr;
    for (int j = 0; j < i + 1; j++) {
      EXPECT_THAT(size_cache, Contains(Pair(subexpr, i + 2 - j)));
      if (j == i) break;
      subexpr = &(subexpr->boolean_negation());
    }
  }
}

TEST(SizeTest, SizeOfBinaryBooleanExpressionAddsOneAndCached) {
  ASSERT_OK_AND_ASSIGN(Expression expr, StringToAST("true && false"));
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(3));
  EXPECT_THAT(size_cache, UnorderedElementsAre(Pair(&expr, 3)));
}

TEST(SizeTest, SizeOfBinaryNonBooleanExpressionAddsOneAndCached) {
  ASSERT_OK_AND_ASSIGN(Expression expr, StringToAST("ether_type != 0x0800"));
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(3));
  EXPECT_THAT(size_cache, UnorderedElementsAre(Pair(&expr, 3)));
}

TEST(SizeTest, SizeOfConstraint1SevenAndCached) {
  ASSERT_OK_AND_ASSIGN(
      Expression expr,
      StringToAST("ether_type != 0x0800 && ether_type != 0x86dd;"));
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(7));
  EXPECT_THAT(size_cache,
              UnorderedElementsAre(Pair(&expr, 7),
                                   Pair(&expr.binary_expression().left(), 3),
                                   Pair(&expr.binary_expression().right(), 3)));
}

TEST(SizeTest, SizeOfConstraint2FifthteenAndCached) {
  ASSERT_OK_AND_ASSIGN(
      Expression expr,
      StringToAST(
          "ttl::mask != 0 -> (is_ip == 1 || is_ipv4 == 1 || is_ipv6 == 1);"));
  auto* or_subexpr = &expr.binary_expression().right();
  auto* or_subsubexpr = &or_subexpr->binary_expression().left();
  SizeCache size_cache;
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(15));
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
  ASSERT_OK_AND_ASSIGN(
      Expression expr,
      StringToAST("ether_type != 0x0800 && ether_type != 0x86dd;"));
  SizeCache size_cache;
  size_cache.insert({&expr, 343});
  EXPECT_THAT(Size(expr, &size_cache), IsOkAndHolds(343));
  EXPECT_THAT(size_cache.size(), Eq(1));
}

TEST(SizeTest, NoCacheOkay) {
  ASSERT_OK_AND_ASSIGN(
      Expression expr,
      StringToAST("ether_type != 0x0800 && ether_type != 0x86dd;"));
  EXPECT_THAT(Size(expr, nullptr), IsOkAndHolds(7));
}

}  // namespace ast
}  // namespace p4_constraints
