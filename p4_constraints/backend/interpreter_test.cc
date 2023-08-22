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
#include <stdint.h>

#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "gutils/parse_text_proto.h"
#include "gutils/status_macros.h"
#include "gutils/status_matchers.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/constraint_source.h"

namespace p4_constraints {
namespace internal_interpreter {
namespace {

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

  // Used to avoid quoting errors. Not important for unit testing.
  const ConstraintSource kDummySource{
      .constraint_string = "source",
      .constraint_location = ast::SourceLocation(),
  };

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

  const EvaluationContext kEvaluationContext{
      .entry = kParsedEntry,
      .source = kDummySource,
  };

  const p4::v1::TableEntry kTableEntry =
      ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "A" }  # integer value 65
        }
      )pb");

  ConstraintInfo MakeConstraintInfo(const Expression& expr) {
    TableInfo table_info = kTableInfo;
    table_info.constraint = expr;
    table_info.constraint_source.constraint_location.set_table_name(
        table_info.name);
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

  // Creates boolean expression `left_arg` `binop` `right_arg`.
  Expression BinaryBooleanExpr(bool left_arg, ast::BinaryOperator binop,
                               bool right_arg) {
    const Expression kTrue =
        ExpressionWithType(kBool, "boolean_constant: true");
    const Expression kFalse =
        ExpressionWithType(kBool, "boolean_constant: false");

    Expression expr;
    expr.mutable_binary_expression()->set_binop(binop);
    *expr.mutable_binary_expression()->mutable_left() =
        (left_arg ? kTrue : kFalse);
    *expr.mutable_binary_expression()->mutable_right() =
        (right_arg ? kTrue : kFalse);
    *expr.mutable_type() = kBool;
    return expr;
  }

  EvaluationContext MakeEvaluationContext(const TableEntry& entry) {
    return EvaluationContext{
        .entry = entry,
        .source = kDummySource,
    };
  }
};

class EvalTest : public EntryMeetsConstraintTest {};
class EvalToBoolCacheTest : public EntryMeetsConstraintTest {};

TEST_F(EntryMeetsConstraintTest, EmptyExpressionErrors) {
  const Expression kExpr;
  EXPECT_THAT(EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(kExpr)),
              StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(EntryMeetsConstraintTest, BooleanConstants) {
  const Expression kConstTrue =
      ExpressionWithType(kBool, "boolean_constant: true");
  const Expression kConstFalse =
      ExpressionWithType(kBool, "boolean_constant: false");
  EXPECT_THAT(EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(kConstTrue)),
              IsOkAndHolds(Eq(true)));
  EXPECT_THAT(
      EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(kConstFalse)),
      IsOkAndHolds(Eq(false)));
}

TEST_F(EntryMeetsConstraintTest, NonBooleanConstraintsAreRejected) {
  for (const Type& type : {kArbitraryInt, kFixedUnsigned16, kFixedUnsigned32}) {
    const Expression kExpr =
        ExpressionWithType(type, R"(integer_constant: "42")");
    EXPECT_THAT(EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(kExpr)),
                StatusIs(StatusCode::kInvalidArgument));
  }

  // Expressions evaluating to non-scalar values should also be rejected.
  for (std::string key : {"exact32", "ternary32", "lpm32", "range32"}) {
    EXPECT_THAT(
        EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(KeyExpr(key))),
        StatusIs(StatusCode::kInvalidArgument));
  }
}

TEST_F(EntryMeetsConstraintTest, EntriesWithLeadingZeroesWork) {
  const Expression exact_equals_num = ExpressionWithType(kBool, R"pb(
    binary_expression {
      binop: EQ
      left {
        type { exact { bitwidth: 32 } }
        key: "exact32"
      }
      right {
        type { exact { bitwidth: 32 } }
        type_cast {
          type { fixed_unsigned { bitwidth: 32 } }
          type_cast {
            type { arbitrary_int {} }
            integer_constant: "65"
          }
        }
      }
    }
  )pb");
  // Sanity check that it holds with original entry.
  ASSERT_THAT(
      EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(exact_equals_num)),
      IsOkAndHolds(true));

  // Modify entry to have leading zeroes.
  p4::v1::TableEntry modified_entry = kTableEntry;
  modified_entry.mutable_match(0)->mutable_exact()->set_value(
      absl::StrCat("\0", kTableEntry.match(0).exact().value()));
  EXPECT_THAT(EntryMeetsConstraint(modified_entry,
                                   MakeConstraintInfo(exact_equals_num)),
              IsOkAndHolds(true));
}

Expression GetPriorityEqualityConstraint(const int32_t priority) {
  constexpr absl::string_view kPriorityEqualityConstraint = R"pb(
    type { boolean {} }
    binary_expression {
      binop: EQ
      left {
        type { arbitrary_int {} }
        attribute_access { attribute_name: "priority" }
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
  const Expression kExpr = GetPriorityEqualityConstraint(0);
  const auto constraint_check_result =
      EntryMeetsConstraint(kTableEntry, MakeConstraintInfo(kExpr));
  ASSERT_THAT(constraint_check_result, IsOkAndHolds(Eq(true)));
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
    const Expression kExpr = GetPriorityEqualityConstraint(0);
    const auto constraint_check_result = EntryMeetsConstraint(
        table_entry_with_priority, MakeConstraintInfo(kExpr));
    ASSERT_THAT(constraint_check_result, IsOkAndHolds(Eq(false)));
  }

  // Equality to the same priority.
  {
    const Expression kExpr = GetPriorityEqualityConstraint(priority);
    const auto constraint_check_result = EntryMeetsConstraint(
        table_entry_with_priority, MakeConstraintInfo(kExpr));
    ASSERT_THAT(constraint_check_result, IsOkAndHolds(Eq(true)));
  }
}

TEST_F(EvalTest, IntegerConstant) {
  for (auto int_str :
       {"0", "-1", "1", "42", "-9042852073498123679518173785123857"}) {
    for (const Type& type :
         {kArbitraryInt, kFixedUnsigned16, kFixedUnsigned32}) {
      const Expression kExpr = ExpressionWithType(
          type, absl::Substitute(R"(integer_constant: "$0")", int_str));
      EvalResult result = mpz_class(int_str);
      EXPECT_THAT(Eval(kExpr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));
    }
  }
}

TEST_F(EvalTest, Key) {
  for (auto& name_and_key_info : kTableInfo.keys_by_name) {
    auto key_name = name_and_key_info.first;
    const Expression kExpr = KeyExpr(key_name);
    EvalResult result = kParsedEntry.keys.find(key_name)->second;
    if (kExpr.type().type_case() == Type::kUnknown ||
        kExpr.type().type_case() == Type::kUnsupported) {
      EXPECT_THAT(Eval(kExpr, kEvaluationContext, nullptr),
                  StatusIs(StatusCode::kInternal));
    } else {
      EXPECT_THAT(Eval(kExpr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));
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
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));
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
    EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                IsOkAndHolds(Eq(result)));
    inner_expr = expr;
  }
}

TEST_F(EvalTest, TypeCast) {
  const Integer max_uint32 = (mpz_class(1) << 32) - 1;  // 2^32 - 1

  for (int n : {-1, 42}) {
    const Integer unsigned_n = (n == -1) ? max_uint32 : mpz_class(n);
    const Expression arbitrary_int = ExpressionWithType(
        kArbitraryInt, absl::Substitute(R"(integer_constant: "$0")", n));

    Expression fixed32 = ExpressionWithType(kFixedUnsigned32, "");
    *fixed32.mutable_type_cast() = arbitrary_int;
    EvalResult result = unsigned_n;
    ASSERT_THAT(Eval(fixed32, kEvaluationContext, nullptr),
                IsOkAndHolds(Eq(result)));

    Expression expr = ExpressionWithType(kExact32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Exact{.value = unsigned_n};
    EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                IsOkAndHolds(Eq(result)));

    expr = ExpressionWithType(kTernary32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Ternary{.value = unsigned_n, .mask = max_uint32};
    EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                IsOkAndHolds(Eq(result)));

    expr = ExpressionWithType(kLpm32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Lpm{.value = unsigned_n, .prefix_length = 32};
    EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                IsOkAndHolds(Eq(result)));

    expr = ExpressionWithType(kRange32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Range{.low = unsigned_n, .high = unsigned_n};
    EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                IsOkAndHolds(Eq(result)));
  }
}

TEST_F(EvalTest, BinaryExpression_BooleanArguments) {
  const Expression kConstTrue =
      ExpressionWithType(kBool, "boolean_constant: true");
  const Expression kConstFalse =
      ExpressionWithType(kBool, "boolean_constant: false");
  auto boolean = [&](bool boolean) -> Expression {
    return boolean ? kConstTrue : kConstFalse;
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
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::OR);
      result = left || right;
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::IMPLIES);
      result = !left || right;
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::EQ);
      result = left == right;
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::NE);
      result = left != right;
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      for (auto comparison : {ast::GT, ast::GE, ast::LT, ast::LE}) {
        expr.mutable_binary_expression()->set_binop(comparison);
        EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
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
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::NE);
      result = left != right;
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::GT);
      result = left > right;
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::GE);
      result = left >= right;
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::LT);
      result = left < right;
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::LE);
      result = left <= right;
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                  IsOkAndHolds(Eq(result)));

      for (auto boolean_op : {ast::AND, ast::OR, ast::IMPLIES}) {
        expr.mutable_binary_expression()->set_binop(boolean_op);
        EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
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
    EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                IsOkAndHolds(Eq(result)));

    expr.mutable_binary_expression()->set_binop(ast::NE);
    result = false;
    EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
                IsOkAndHolds(Eq(result)));

    for (auto binop : {ast::GT, ast::GE, ast::LT, ast::LE, ast::AND, ast::OR,
                       ast::IMPLIES}) {
      expr.mutable_binary_expression()->set_binop(binop);
      EXPECT_THAT(Eval(expr, kEvaluationContext, nullptr),
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
  EXPECT_THAT(Eval(FieldAccessExpr("value", "exact32", kFixedUnsigned32),
                   MakeEvaluationContext(entry), nullptr),
              IsOkAndHolds(Eq(result)));
  for (std::string bad_field : {"mask", "prefix_length", "low", "high", "xy"}) {
    EXPECT_THAT(Eval(FieldAccessExpr(bad_field, "exact32", kFixedUnsigned32),
                     MakeEvaluationContext(entry), nullptr),
                StatusIs(StatusCode::kInternal));
  }

  entry = kParsedEntry;  // Reset.
  entry.keys["ternary32"] = Ternary{.value = value, .mask = value2};
  EXPECT_THAT(Eval(FieldAccessExpr("value", "ternary32", kFixedUnsigned32),
                   MakeEvaluationContext(entry), nullptr),
              IsOkAndHolds(Eq(result)));
  EXPECT_THAT(Eval(FieldAccessExpr("mask", "ternary32", kFixedUnsigned32),
                   MakeEvaluationContext(entry), nullptr),
              IsOkAndHolds(Eq(result2)));
  for (std::string bad_field : {"prefix_length", "low", "high", "xy", "foo"}) {
    EXPECT_THAT(Eval(FieldAccessExpr(bad_field, "ternary32", kFixedUnsigned32),
                     MakeEvaluationContext(entry), nullptr),
                StatusIs(StatusCode::kInternal));
  }

  entry = kParsedEntry;  // Reset.
  entry.keys["lpm32"] = Lpm{.value = value, .prefix_length = value2};
  EXPECT_THAT(Eval(FieldAccessExpr("value", "lpm32", kFixedUnsigned32),
                   MakeEvaluationContext(entry), nullptr),
              IsOkAndHolds(Eq(result)));
  EXPECT_THAT(Eval(FieldAccessExpr("prefix_length", "lpm32", kFixedUnsigned32),
                   MakeEvaluationContext(entry), nullptr),
              IsOkAndHolds(Eq(result2)));
  for (std::string bad_field : {"mask", "low", "high", "xy", "foo", "bar"}) {
    EXPECT_THAT(Eval(FieldAccessExpr(bad_field, "lpm32", kFixedUnsigned32),
                     MakeEvaluationContext(entry), nullptr),
                StatusIs(StatusCode::kInternal));
  }

  entry = kParsedEntry;  // Reset.
  entry.keys["range32"] = Range{.low = value, .high = value2};
  EXPECT_THAT(Eval(FieldAccessExpr("low", "range32", kFixedUnsigned32),
                   MakeEvaluationContext(entry), nullptr),
              IsOkAndHolds(Eq(result)));
  EXPECT_THAT(Eval(FieldAccessExpr("high", "range32", kFixedUnsigned32),
                   MakeEvaluationContext(entry), nullptr),
              IsOkAndHolds(Eq(result2)));
  for (std::string bad_field : {"value", "mask", "prefix_length", "xy", "fo"}) {
    EXPECT_THAT(Eval(FieldAccessExpr(bad_field, "range32", kFixedUnsigned32),
                     MakeEvaluationContext(entry), nullptr),
                StatusIs(StatusCode::kInternal));
  }
}

TEST_F(EvalToBoolCacheTest, CacheGetsPopulatedForBooleanConstant) {
  const Expression kConstTrue =
      ExpressionWithType(kBool, "boolean_constant: true");
  const Expression kConstFalse =
      ExpressionWithType(kBool, "boolean_constant: false");

  EvaluationCache eval_cache;
  ASSERT_OK(EvalToBool(kConstTrue, kEvaluationContext, &eval_cache));
  EXPECT_THAT(eval_cache, UnorderedElementsAre(Pair(&kConstTrue, true)));

  ASSERT_OK(EvalToBool(kConstFalse, kEvaluationContext, &eval_cache));
  EXPECT_THAT(eval_cache, UnorderedElementsAre(Pair(&kConstTrue, true),
                                               Pair(&kConstFalse, false)));
}

TEST_F(EvalToBoolCacheTest, CacheGetsPopulatedForBooleanNegation) {
  for (bool boolean : {true, false}) {
    Expression inner_expr = ExpressionWithType(
        kBool, absl::Substitute("boolean_constant: $0", boolean));
    Expression expr = ExpressionWithType(kBool, "");
    // Create a chain of 5 nested negations.
    for (int i = 0; i < 4; i++) {
      *expr.mutable_boolean_negation() = inner_expr;
      inner_expr = expr;
      expr = ExpressionWithType(kBool, "");
    }
    *expr.mutable_boolean_negation() = inner_expr;
    EvaluationCache eval_cache;
    ASSERT_OK(EvalToBool(expr, kEvaluationContext, &eval_cache));
    EXPECT_THAT(eval_cache.size(), Eq(6));
    const Expression* subexpr = &expr;
    // Check that all negations are cached
    for (int i = 0; i < 6; i++) {
      EXPECT_THAT(
          eval_cache,
          Contains(Pair(subexpr,
                        *EvalToBool(*subexpr, kEvaluationContext, nullptr))));
      if (i == 5) break;
      subexpr = &(subexpr->boolean_negation());
    }
  }
}

TEST_F(EvalToBoolCacheTest, CacheGetsPopulatedForBooleanComparison) {
  const Expression kConstraint = BinaryBooleanExpr(true, ast::AND, false);
  EvaluationCache eval_cache;
  ASSERT_OK(EvalToBool(kConstraint, kEvaluationContext, &eval_cache));

  ASSERT_OK_AND_ASSIGN(bool result1,
                       EvalToBool(kConstraint, kEvaluationContext, nullptr));
  ASSERT_OK_AND_ASSIGN(bool result2,
                       EvalToBool(kConstraint.binary_expression().left(),
                                  kEvaluationContext, nullptr));
  ASSERT_OK_AND_ASSIGN(bool result3,
                       EvalToBool(kConstraint.binary_expression().right(),
                                  kEvaluationContext, nullptr));

  EXPECT_THAT(eval_cache,
              UnorderedElementsAre(
                  Pair(&kConstraint, result1),
                  Pair(&kConstraint.binary_expression().left(), result2),
                  Pair(&kConstraint.binary_expression().right(), result3)));
}

TEST_F(EvalToBoolCacheTest, CacheRespectsShortCircuit) {
  const Expression kConstraint = BinaryBooleanExpr(true, ast::OR, false);
  EvaluationCache eval_cache;
  ASSERT_OK(EvalToBool(kConstraint, kEvaluationContext, &eval_cache));
  ASSERT_OK(EvalToBool(kConstraint, kEvaluationContext, &eval_cache));
  ASSERT_OK_AND_ASSIGN(bool result1,
                       EvalToBool(kConstraint, kEvaluationContext, nullptr));
  ASSERT_OK_AND_ASSIGN(bool result2,
                       EvalToBool(kConstraint.binary_expression().left(),
                                  kEvaluationContext, nullptr));
  EXPECT_THAT(eval_cache,
              UnorderedElementsAre(
                  Pair(&kConstraint, result1),
                  Pair(&kConstraint.binary_expression().left(), result2)));
}

TEST_F(EvalToBoolCacheTest, CacheGetsPopulatedForNonBooleanComparison) {
  const Expression kConstraint = GetPriorityEqualityConstraint(42);
  EvaluationCache eval_cache;
  ASSERT_OK(EvalToBool(kConstraint, kEvaluationContext, &eval_cache));
  ASSERT_OK_AND_ASSIGN(bool result1,
                       EvalToBool(kConstraint, kEvaluationContext, nullptr));
  EXPECT_THAT(eval_cache, UnorderedElementsAre(Pair(&kConstraint, result1)));
}

TEST_F(EvalToBoolCacheTest, CacheIsUsed) {
  const Expression kConstraint = BinaryBooleanExpr(true, ast::OR, true);
  EvaluationCache eval_cache;
  eval_cache.insert({&kConstraint, false});
  ASSERT_OK(EvalToBool(kConstraint, kEvaluationContext, &eval_cache));
  EXPECT_THAT(eval_cache.size(), Eq(1));
  EXPECT_THAT(*EvalToBool(kConstraint, kEvaluationContext, &eval_cache),
              Eq(false));
}

class MinimalSubexpressionLeadingToEvalResultTest
    : public EntryMeetsConstraintTest {
 public:
  absl::StatusOr<const Expression*>
  MinimalSubexpressionLeadingToEvalResultHelper(const Expression& kConstraint) {
    EvaluationCache eval_cache;
    ast::SizeCache size_cache;
    return MinimalSubexpressionLeadingToEvalResult(
        kConstraint, kEvaluationContext, eval_cache, size_cache);
  }
};

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainBoolConstantIsConstant) {
  const Expression kConstTrue =
      ExpressionWithType(kBool, "boolean_constant: true");
  const Expression kConstFalse =
      ExpressionWithType(kBool, "boolean_constant: false");

  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstTrue),
              IsOkAndHolds(Eq(&kConstTrue)));

  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstFalse),
              IsOkAndHolds(Eq(&kConstFalse)));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainNegationIsInnerExpression) {
  for (bool boolean : {true, false}) {
    auto inner_expr = ExpressionWithType(
        kBool, absl::Substitute("boolean_constant: $0", boolean));
    auto expr = ExpressionWithType(kBool, "");
    // Create a chain of 5 nested negations.
    for (int i = 0; i < 4; i++) {
      *expr.mutable_boolean_negation() = inner_expr;
      inner_expr = expr;
      expr = ExpressionWithType(kBool, "");
    }
    *expr.mutable_boolean_negation() = inner_expr;
    const auto* result = &expr;
    // Get the location of the inner most expression.
    for (int i = 0; i < 5; i++) {
      result = &(result->boolean_negation());
    }
    const auto* root = &expr;
    // Check that all negations return inner most expression.
    for (int i = 0; i < 5; i++) {
      EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(*root),
                  IsOkAndHolds(Eq(result)));
      root = &(root->boolean_negation());
    }
  }
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainNonBooleanComparisonIsComparison) {
  const Expression kConstraint = GetPriorityEqualityConstraint(42);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint)));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainIntegerConstantIsError) {
  for (auto int_str :
       {"0", "-1", "1", "42", "-9042852073498123679518173785123857"}) {
    for (const Type& type :
         {kArbitraryInt, kFixedUnsigned16, kFixedUnsigned32}) {
      auto expr = ExpressionWithType(
          type, absl::Substitute(R"(integer_constant: "$0")", int_str));
      EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(expr),
                  StatusIs(StatusCode::kInternal));
    }
  }
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest, ExplainKeyIsError) {
  for (auto& name_and_key_info : kTableInfo.keys_by_name) {
    auto key_name = name_and_key_info.first;
    auto expr = KeyExpr(key_name);
    EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(expr),
                StatusIs(StatusCode::kInternal));
  }
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest, ExplainTrueANDIsAND) {
  const Expression kConstraint = BinaryBooleanExpr(true, ast::AND, true);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint)));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainSingleFalseANDIsFalseArg) {
  const Expression kConstraint = BinaryBooleanExpr(true, ast::AND, false);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint.binary_expression().right())));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainDoubleFalseANDIsLeftArg) {
  const Expression kConstraint = BinaryBooleanExpr(false, ast::AND, false);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint.binary_expression().left())));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainSingleTrueORIsTrueArg) {
  const Expression kConstraint = BinaryBooleanExpr(true, ast::OR, false);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint.binary_expression().left())));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainDoubleTrueORIsLeftArg) {
  const Expression kConstraint = BinaryBooleanExpr(true, ast::OR, true);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint.binary_expression().left())));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest, ExplainFalseORIsOR) {
  const Expression kConstraint = BinaryBooleanExpr(false, ast::OR, false);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint)));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainTrueIMPLIESWithFalseAncedentIsFalseAntecedent) {
  const Expression kConstraint = BinaryBooleanExpr(false, ast::IMPLIES, false);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint.binary_expression().left())));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainTrueIMPLIESWithTrueConsequentIsTrueConsequent) {
  const Expression kConstraint = BinaryBooleanExpr(true, ast::IMPLIES, true);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint.binary_expression().right())));
}

TEST_F(
    MinimalSubexpressionLeadingToEvalResultTest,
    ExplainTrueIMPLIESWithFalseAntecedentAndTrueConsequentIsFalseAntecedent) {
  const Expression kConstraint = BinaryBooleanExpr(false, ast::IMPLIES, true);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint.binary_expression().left())));
}

TEST_F(MinimalSubexpressionLeadingToEvalResultTest,
       ExplainFalseIMPLIESIsIMPLIES) {
  const Expression kConstraint = BinaryBooleanExpr(true, ast::IMPLIES, false);
  EXPECT_THAT(MinimalSubexpressionLeadingToEvalResultHelper(kConstraint),
              IsOkAndHolds(Eq(&kConstraint)));
}
}  // namespace
}  // namespace internal_interpreter
}  // namespace p4_constraints
