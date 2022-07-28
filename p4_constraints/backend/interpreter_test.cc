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

#include "p4_constraints/backend/interpreter.h"

#include <gmock/gmock.h>
#include <gmpxx.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "gutils/parse_text_proto.h"
#include "gutils/status_matchers.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/ast.proto.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/backend/type_checker.h"
#include "p4_constraints/frontend/lexer.h"
#include "p4_constraints/frontend/parser.h"

namespace p4_constraints {
namespace internal_interpreter {

using ::absl::StatusCode;
using ::gutils::ParseTextProtoOrDie;
using ::gutils::testing::status::IsOkAndHolds;
using ::gutils::testing::status::StatusIs;
using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::Type;
using ::testing::Contains;
using ::testing::Eq;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

class EntryMeetsConstraintTest : public ::testing::Test {
 public:
  const Type kUnknown = ParseTextProtoOrDie<Type>("unknown {}");
  const Type kUnsupported =
      ParseTextProtoOrDie<Type>(R"pb(unsupported { name: "optional" })pb");
  const Type kBool = ParseTextProtoOrDie<Type>("boolean {}");
  const Type kArbitraryInt = ParseTextProtoOrDie<Type>("arbitrary_int {}");
  const Type kFixedUnsigned16 =
      ParseTextProtoOrDie<Type>("fixed_unsigned { bitwidth: 16 }");
  const Type kFixedUnsigned32 =
      ParseTextProtoOrDie<Type>("fixed_unsigned { bitwidth: 32 }");
  const Type kExact32 = ParseTextProtoOrDie<Type>("exact { bitwidth: 32 }");
  const Type kTernary32 = ParseTextProtoOrDie<Type>("ternary { bitwidth: 32 }");
  const Type kLpm32 = ParseTextProtoOrDie<Type>("lpm { bitwidth: 32 }");
  const Type kRange32 = ParseTextProtoOrDie<Type>("range { bitwidth: 32 }");
  const Type kOptional32 =
      ParseTextProtoOrDie<Type>("optional_match { bitwidth: 32 }");

  const TableInfo kTableInfo{
      .id = 1,
      .name = "table",
      .constraint = {},  // To be filled in later.
      .keys_by_id =
          {
              {1, {1, "exact32", kExact32}},
              // For testing purposes, fine to omit the other keys here.
          },
      .keys_by_name = {
          {"exact32", {1, "exact32", kExact32}},
          {"ternary32", {2, "ternary32", kTernary32}},
          {"lpm32", {3, "lpm32", kLpm32}},
          {"range32", {4, "range32", kRange32}},
          {"optional32", {5, "optional32", kOptional32}},
      }};

  const TableEntry kParsedEntry{
      .table_name = "table",
      .keys = {
          {"exact32", {Exact{.value = mpz_class(42)}}},
          {"ternary32",
           {Ternary{.value = mpz_class(12), .mask = mpz_class(128)}}},
          {"lpm32",
           {Lpm{.value = mpz_class(0), .prefix_length = mpz_class(32)}}},
          {"range32", {Range{.low = mpz_class(5), .high = mpz_class(500)}}},
          {"optional32",
           {Ternary{.value = mpz_class(12),
                    .mask = (mpz_class(1) << 32) - mpz_class(1)}}},
      }};

  const p4::v1::TableEntry kTableEntry =
      ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "1234" }
        }
      )pb");

  ConstraintInfo MakeConstraintInfo(const Expression& expr) {
    TableInfo table_info = kTableInfo;
    table_info.constraint = expr;
    return {{table_info.id, table_info}};
  }

  static Expression ExpressionWithType(const Type& type,
                                       const std::string& expr_string) {
    Expression expr = ParseTextProtoOrDie<Expression>(expr_string);
    *expr.mutable_type() = type;
    return expr;
  }

  Expression KeyExpr(const std::string& key) {
    Type type = kTableInfo.keys_by_name.find(key)->second.type;
    return ExpressionWithType(type, "key: \"" + key + "\"");
  }

  Expression FieldAccessExpr(const std::string& field, const std::string& key,
                             const Type& type) {
    Expression expr;
    *expr.mutable_field_access()->mutable_field() = field;
    *expr.mutable_field_access()->mutable_expr() = KeyExpr(key);
    *expr.mutable_type() = type;
    return expr;
  }
};

class EvalTest : public EntryMeetsConstraintTest {};
class EvalToBoolCacheTest : public EntryMeetsConstraintTest {};

TEST_F(EntryMeetsConstraintTest, EmptyExpressionErrors) {
  Expression expr;
  EXPECT_THAT(EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(expr)),
              StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(EntryMeetsConstraintTest, BooleanConstants) {
  Expression const_true = ExpressionWithType(kBool, "boolean_constant: true");
  Expression const_false = ExpressionWithType(kBool, "boolean_constant: false");
  EXPECT_THAT(EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(const_true)),
              IsOkAndHolds(Eq(true)));
  EXPECT_THAT(
      EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(const_false)),
      IsOkAndHolds(Eq(false)));
}

TEST_F(EntryMeetsConstraintTest, NonBooleanConstraintsAreRejected) {
  for (const Type& type : {kArbitraryInt, kFixedUnsigned16, kFixedUnsigned32}) {
    Expression expr = ExpressionWithType(type, R"(integer_constant: "42")");
    EXPECT_THAT(EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(expr)),
                StatusIs(StatusCode::kInvalidArgument));
  }

  // Expressions evaluating to non-scalar values should also be rejected.
  for (std::string key : {"exact32", "ternary32", "lpm32", "range32"}) {
    EXPECT_THAT(
        EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(KeyExpr(key))),
        StatusIs(StatusCode::kInvalidArgument));
  }
}

Expression GetPriorityEqualityConstraint(const int32_t priority) {
  constexpr absl::string_view kPriorityEqualityConstraint = R"pb(
    type { boolean {} }
    binary_expression {
      binop: EQ
      left {
        type { arbitrary_int {} }
        metadata_access { metadata_name: "priority" }
      }
      right {
        type { arbitrary_int {} }
        integer_constant: "$0"
      }
    }
  )pb";

  return ParseTextProtoOrDie<Expression>(
      absl::Substitute(kPriorityEqualityConstraint, priority));
}

TEST_F(EntryMeetsConstraintTest, PriorityConstraintWorksWithDefaultPriority) {
  const Expression expr = GetPriorityEqualityConstraint(0);
  const auto constraint_check_result =
      EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(expr));
  ASSERT_THAT(constraint_check_result, IsOkAndHolds(true));
}

TEST_F(EntryMeetsConstraintTest,
       PriorityConstraintWorksWithNonDefaultPriority) {
  constexpr absl::string_view kTableEntryWithPriority = R"pb(
    table_id: 1
    match {
      field_id: 1
      exact { value: "1234" }
    }
    priority: $0
  )pb";

  const int32_t priority = 10;

  const p4::v1::TableEntry table_entry_with_priority =
      ParseTextProtoOrDie<p4::v1::TableEntry>(
          absl::Substitute(kTableEntryWithPriority, priority));

  // Equality to a different priority.
  {
    const Expression expr = GetPriorityEqualityConstraint(0);
    const auto constraint_check_result = EntryMeetsConstraint(
        table_entry_with_priority, MakeConstraintInfo(expr));
    ASSERT_THAT(constraint_check_result, IsOkAndHolds(false));
  }

  // Equality to the same priority.
  {
    const Expression expr = GetPriorityEqualityConstraint(priority);
    const auto constraint_check_result = EntryMeetsConstraint(
        table_entry_with_priority, MakeConstraintInfo(expr));
    ASSERT_THAT(constraint_check_result, IsOkAndHolds(true));
  }
}

TEST_F(EvalTest, IntegerConstant) {
  for (auto int_str :
       {"0", "-1", "1", "42", "-9042852073498123679518173785123857"}) {
    for (const Type& type :
         {kArbitraryInt, kFixedUnsigned16, kFixedUnsigned32}) {
      Expression expr = ExpressionWithType(
          type, absl::Substitute(R"(integer_constant: "$0")", int_str));
      EvalResult result = mpz_class(int_str);
      EXPECT_THAT(Eval(expr, TableEntry{}, nullptr), IsOkAndHolds(Eq(result)));
    }
  }
}

TEST_F(EvalTest, Key) {
  for (auto& name_and_key_info : kTableInfo.keys_by_name) {
    auto key_name = name_and_key_info.first;
    Expression expr = KeyExpr(key_name);
    EvalResult result = kParsedEntry.keys.find(key_name)->second;
    if (expr.type().type_case() == Type::kUnknown ||
        expr.type().type_case() == Type::kUnsupported) {
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr),
                  StatusIs(StatusCode::kInternal));
    } else {
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));
    }
  }
}

TEST_F(EvalTest, BooleanNegation) {
  for (bool boolean : {true, false}) {
    Expression inner_expr = ExpressionWithType(
        kBool, absl::Substitute("boolean_constant: $0", boolean));
    for (int i = 0; i < 4; i++) {
      Expression expr = ExpressionWithType(kBool, "");
      *expr.mutable_boolean_negation() = inner_expr;
      EvalResult result = (i % 2 == 0) ? (!boolean) : boolean;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));
      inner_expr = expr;
    }
  }
}

TEST_F(EvalTest, ArithmeticNegation) {
  Integer value = mpz_class(42);
  Expression inner_expr =
      ExpressionWithType(kArbitraryInt, R"(integer_constant: "42")");
  for (int i = 0; i < 4; i++) {
    Expression expr = ExpressionWithType(kArbitraryInt, "");
    *expr.mutable_arithmetic_negation() = inner_expr;
    EvalResult result = (i % 2 == 0) ? (0 - value) : value;
    EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));
    inner_expr = expr;
  }
}

TEST_F(EvalTest, TypeCast) {
  const Integer max_uint32 = (mpz_class(1) << 32) - 1;  // 2^32 - 1

  for (int n : {-1, 42}) {
    const Integer unsigned_n = (n == -1) ? max_uint32 : mpz_class(n);
    Expression arbitrary_int = ExpressionWithType(
        kArbitraryInt, absl::Substitute(R"(integer_constant: "$0")", n));

    Expression fixed32 = ExpressionWithType(kFixedUnsigned32, "");
    *fixed32.mutable_type_cast() = arbitrary_int;
    EvalResult result = unsigned_n;
    ASSERT_THAT(Eval(fixed32, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

    Expression expr = ExpressionWithType(kExact32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Exact{.value = unsigned_n};
    EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

    expr = ExpressionWithType(kTernary32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Ternary{.value = unsigned_n, .mask = max_uint32};
    EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

    expr = ExpressionWithType(kLpm32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Lpm{.value = unsigned_n, .prefix_length = 32};
    EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

    expr = ExpressionWithType(kRange32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Range{.low = unsigned_n, .high = unsigned_n};
    EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));
  }
}

TEST_F(EvalTest, BinaryExpression_BooleanArguments) {
  const Expression const_true =
      ExpressionWithType(kBool, "boolean_constant: true");
  const Expression const_false =
      ExpressionWithType(kBool, "boolean_constant: false");
  auto boolean = [&](bool boolean) -> Expression {
    return boolean ? const_true : const_false;
  };

  for (bool left : {true, false}) {
    for (bool right : {true, false}) {
      Expression expr = ExpressionWithType(
          kBool, absl::Substitute("binary_expression { left {$0} right {$1} }",
                                  boolean(left).DebugString(),
                                  boolean(right).DebugString()));
      EvalResult result;

      expr.mutable_binary_expression()->set_binop(ast::AND);
      result = left && right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::OR);
      result = left || right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::IMPLIES);
      result = !left || right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::EQ);
      result = left == right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::NE);
      result = left != right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      for (auto comparison : {ast::GT, ast::GE, ast::LT, ast::LE}) {
        expr.mutable_binary_expression()->set_binop(comparison);
        EXPECT_THAT(Eval(expr, kParsedEntry, nullptr),
                    StatusIs(StatusCode::kInternal));
      }
    }
  }
}

TEST_F(EvalTest, BinaryExpression_NumericArguments) {
  auto int_const = [&](Integer n) -> Expression {
    return ExpressionWithType(kArbitraryInt,
                              "integer_constant: \"" + n.get_str() + "\"");
  };
  const std::vector<Integer> values{
      mpz_class(-1),
      mpz_class(0),
      mpz_class(42),
      mpz_class("-452389348125871341098532412564"),
      mpz_class("53871347531398537818732785237812312987523"),
  };

  for (const Integer& left : values) {
    for (const Integer& right : values) {
      Expression expr = ExpressionWithType(
          kBool, absl::Substitute("binary_expression { left {$0} right {$1} }",
                                  int_const(left).DebugString(),
                                  int_const(right).DebugString()));
      EvalResult result;

      expr.mutable_binary_expression()->set_binop(ast::EQ);
      result = left == right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::NE);
      result = left != right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::GT);
      result = left > right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::GE);
      result = left >= right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::LT);
      result = left < right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::LE);
      result = left <= right;
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

      for (auto boolean_op : {ast::AND, ast::OR, ast::IMPLIES}) {
        expr.mutable_binary_expression()->set_binop(boolean_op);
        EXPECT_THAT(Eval(expr, kParsedEntry, nullptr),
                    StatusIs(StatusCode::kInternal));
      }
    }
  }
}

TEST_F(EvalTest, BinaryExpression_CompositeArguments) {
  for (auto key : {"exact32", "ternary32", "lpm32", "range32"}) {
    Expression expr = ExpressionWithType(
        kBool, absl::Substitute("binary_expression { left {$0} right {$0} }",
                                KeyExpr(key).DebugString()));
    EvalResult result;

    expr.mutable_binary_expression()->set_binop(ast::EQ);
    result = true;
    EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

    expr.mutable_binary_expression()->set_binop(ast::NE);
    result = false;
    EXPECT_THAT(Eval(expr, kParsedEntry, nullptr), IsOkAndHolds(Eq(result)));

    for (auto binop : {ast::GT, ast::GE, ast::LT, ast::LE, ast::AND, ast::OR,
                       ast::IMPLIES}) {
      expr.mutable_binary_expression()->set_binop(binop);
      EXPECT_THAT(Eval(expr, kParsedEntry, nullptr),
                  StatusIs(StatusCode::kInternal));
    }
  }
}

TEST_F(EvalTest, FieldAccess) {
  Integer value = mpz_class(42);
  EvalResult result = value;
  Integer value2 = mpz_class(-21);
  EvalResult result2 = value2;

  TableEntry entry = kParsedEntry;
  entry.keys["exact32"] = Exact{.value = value};
  EXPECT_THAT(Eval(FieldAccessExpr("value", "exact32", kFixedUnsigned32), entry,
                   nullptr),
              IsOkAndHolds(Eq(result)));
  for (std::string bad_field : {"mask", "prefix_length", "low", "high", "xy"}) {
    EXPECT_THAT(Eval(FieldAccessExpr(bad_field, "exact32", kFixedUnsigned32),
                     entry, nullptr),
                StatusIs(StatusCode::kInternal));
  }

  entry = kParsedEntry;  // Reset.
  entry.keys["ternary32"] = Ternary{.value = value, .mask = value2};
  EXPECT_THAT(Eval(FieldAccessExpr("value", "ternary32", kFixedUnsigned32),
                   entry, nullptr),
              IsOkAndHolds(Eq(result)));
  EXPECT_THAT(Eval(FieldAccessExpr("mask", "ternary32", kFixedUnsigned32),
                   entry, nullptr),
              IsOkAndHolds(Eq(result2)));
  for (std::string bad_field : {"prefix_length", "low", "high", "xy", "foo"}) {
    EXPECT_THAT(Eval(FieldAccessExpr(bad_field, "ternary32", kFixedUnsigned32),
                     entry, nullptr),
                StatusIs(StatusCode::kInternal));
  }

  entry = kParsedEntry;  // Reset.
  entry.keys["lpm32"] = Lpm{.value = value, .prefix_length = value2};
  EXPECT_THAT(
      Eval(FieldAccessExpr("value", "lpm32", kFixedUnsigned32), entry, nullptr),
      IsOkAndHolds(Eq(result)));
  EXPECT_THAT(Eval(FieldAccessExpr("prefix_length", "lpm32", kFixedUnsigned32),
                   entry, nullptr),
              IsOkAndHolds(Eq(result2)));
  for (std::string bad_field : {"mask", "low", "high", "xy", "foo", "bar"}) {
    EXPECT_THAT(Eval(FieldAccessExpr(bad_field, "lpm32", kFixedUnsigned32),
                     entry, nullptr),
                StatusIs(StatusCode::kInternal));
  }

  entry = kParsedEntry;  // Reset.
  entry.keys["range32"] = Range{.low = value, .high = value2};
  EXPECT_THAT(
      Eval(FieldAccessExpr("low", "range32", kFixedUnsigned32), entry, nullptr),
      IsOkAndHolds(Eq(result)));
  EXPECT_THAT(Eval(FieldAccessExpr("high", "range32", kFixedUnsigned32), entry,
                   nullptr),
              IsOkAndHolds(Eq(result2)));
  for (std::string bad_field : {"value", "mask", "prefix_length", "xy", "fo"}) {
    EXPECT_THAT(Eval(FieldAccessExpr(bad_field, "range32", kFixedUnsigned32),
                     entry, nullptr),
                StatusIs(StatusCode::kInternal));
  }
}

TEST_F(EvalToBoolCacheTest, CacheGetsPopulatedForBooleanConstant) {
  Expression const_true = ExpressionWithType(kBool, "boolean_constant: true");
  Expression const_false = ExpressionWithType(kBool, "boolean_constant: false");
  EvaluationCache eval_cache;
  ASSERT_OK(EvalToBool(const_true, TableEntry{}, &eval_cache));
  EXPECT_THAT(eval_cache, UnorderedElementsAre(Pair(&const_true, true)));
  ASSERT_OK(EvalToBool(const_false, TableEntry{}, &eval_cache));
  EXPECT_THAT(eval_cache, UnorderedElementsAre(Pair(&const_true, true),
                                               Pair(&const_false, false)));
}

TEST_F(EvalToBoolCacheTest, CacheGetsPopulatedForBooleanNegation) {
  for (bool boolean : {true, false}) {
    Expression inner_expr = ExpressionWithType(
        kBool, absl::Substitute("boolean_constant: $0", boolean));
    Expression expr = ExpressionWithType(kBool, "");
    for (int i = 0; i < 4; i++) {
      *expr.mutable_boolean_negation() = inner_expr;
      inner_expr = expr;
      expr = ExpressionWithType(kBool, "");
    }
    *expr.mutable_boolean_negation() = inner_expr;
    EvaluationCache eval_cache;
    ASSERT_OK(EvalToBool(expr, TableEntry{}, &eval_cache));
    EXPECT_THAT(eval_cache.size(), Eq(6));
    const Expression* subexpr = &expr;
    for (int i = 0; i < 6; i++) {
      EXPECT_THAT(eval_cache,
                  Contains(Pair(subexpr,
                                *EvalToBool(*subexpr, TableEntry{}, nullptr))));
      if (i == 5) break;
      subexpr = &(subexpr->boolean_negation());
    }
  }
}

absl::StatusOr<Expression> MakeTypedConstraintFromString(
    absl::string_view constraint_string,
    const p4_constraints::TableInfo& table_context) {
  ASSIGN_OR_RETURN(
      Expression constraint,
      ParseConstraint(Tokenize(constraint_string, ast::SourceLocation())));
  RETURN_IF_ERROR(InferAndCheckTypes(&constraint, table_context));
  return constraint;
}

TEST_F(EvalToBoolCacheTest, CacheGetsPopulatedForBooleanComparison) {
  ASSERT_OK_AND_ASSIGN(Expression constraint, MakeTypedConstraintFromString(
                                                  "true && false;", kTableInfo))
  EvaluationCache eval_cache;
  ASSERT_OK(EvalToBool(constraint, kParsedEntry, &eval_cache));
  ASSERT_OK_AND_ASSIGN(bool result1,
                       EvalToBool(constraint, kParsedEntry, nullptr));
  ASSERT_OK_AND_ASSIGN(
      bool result2,
      EvalToBool(constraint.binary_expression().left(), kParsedEntry, nullptr));
  ASSERT_OK_AND_ASSIGN(bool result3,
                       EvalToBool(constraint.binary_expression().right(),
                                  kParsedEntry, nullptr));
  EXPECT_THAT(eval_cache,
              UnorderedElementsAre(
                  Pair(&constraint, result1),
                  Pair(&constraint.binary_expression().left(), result2),
                  Pair(&constraint.binary_expression().right(), result3)));
}

TEST_F(EvalToBoolCacheTest, CacheRespectsShortCircuit) {
  ASSERT_OK_AND_ASSIGN(Expression constraint, MakeTypedConstraintFromString(
                                                  "true || false;", kTableInfo))
  EvaluationCache eval_cache;
  ASSERT_OK(EvalToBool(constraint, kParsedEntry, &eval_cache));
  ASSERT_OK_AND_ASSIGN(bool result1,
                       EvalToBool(constraint, kParsedEntry, nullptr));
  ASSERT_OK_AND_ASSIGN(
      bool result2,
      EvalToBool(constraint.binary_expression().left(), kParsedEntry, nullptr));
  EXPECT_THAT(eval_cache,
              UnorderedElementsAre(
                  Pair(&constraint, result1),
                  Pair(&constraint.binary_expression().left(), result2)));
}

TEST_F(EvalToBoolCacheTest, CacheGetsPopulatedForNonBooleanComparison) {
  ASSERT_OK_AND_ASSIGN(
      Expression constraint,
      MakeTypedConstraintFromString("exact32::value == 10;", kTableInfo))
  EvaluationCache eval_cache;
  ASSERT_OK(EvalToBool(constraint, kParsedEntry, &eval_cache));
  ASSERT_OK_AND_ASSIGN(bool result1,
                       EvalToBool(constraint, kParsedEntry, nullptr));
  EXPECT_THAT(eval_cache, UnorderedElementsAre(Pair(&constraint, result1)));
}

TEST_F(EvalToBoolCacheTest, CacheIsUsed) {
  ASSERT_OK_AND_ASSIGN(Expression constraint, MakeTypedConstraintFromString(
                                                  "true || true;", kTableInfo))
  EvaluationCache eval_cache;
  eval_cache.insert({&constraint, false});
  EXPECT_THAT(EvalToBool(constraint, kParsedEntry, &eval_cache),
              IsOkAndHolds(false));
}

}  // namespace internal_interpreter
}  // namespace p4_constraints
