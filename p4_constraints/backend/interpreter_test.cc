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

#include <gmpxx.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4/v1/p4runtime.pb.h"
#include "util/parse_text_proto.h"
#include "util/status_matchers.h"
#include "util/status.h"

namespace p4_constraints {
namespace internal_interpreter {

using ::absl::StatusCode;
using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::Type;
using ::testing::Eq;
using ::util::testing::status::IsOkAndHolds;
using ::util::testing::status::StatusIs;
using ::util::ParseTextProtoOrDie;

class EntryMeetsConstraintTest : public ::testing::Test {
 public:
  const Type kUnknown = ParseTextProtoOrDie<Type>("unknown {}");
  const Type kUnsupported =
      ParseTextProtoOrDie<Type>(R"(unsupported { name: "optional" })");
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

  const TableInfo kTableInfo{
      .id = 0,
      .name = "table",
      .constraint = {},  // To be filled in later.
      .keys_by_id = {},  // Not needed for testing.
      .keys_by_name = {
          {"unknown", {0, "unknown", kUnknown}},
          {"unsupported", {0, "unsupported", kUnsupported}},
          {"bool", {0, "bool", kBool}},
          {"int", {0, "int", kArbitraryInt}},
          {"bit16", {0, "bit16", kFixedUnsigned16}},
          {"bit32", {0, "bit32", kFixedUnsigned32}},
          {"exact32", {0, "exact32", kExact32}},
          {"ternary32", {0, "ternary32", kTernary32}},
          {"lpm32", {0, "lpm32", kLpm32}},
          {"range32", {0, "range32", kRange32}},
      }};

  const TableEntry kParsedEntry{
      .table_name = "table",
      .keys = {
          {"unknown", {false}},
          {"unsupported", {false}},
          {"bool", {true}},
          {"int", {mpz_class("-1")}},
          {"bit16", {mpz_class("42")}},
          {"bit32", {mpz_class("200")}},
          {"exact32", {Exact{.value = mpz_class("13")}}},
          {"ternary32",
           {Ternary{.value = mpz_class("12"), .mask = mpz_class("128")}}},
          {"lpm32",
           {Lpm{.value = mpz_class("0"), .prefix_length = mpz_class("32")}}},
          {"range32", {Range{.low = mpz_class("5"), .high = mpz_class("500")}}},
      }};

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

TEST_F(EntryMeetsConstraintTest, EmptyExpressionErrors) {
  Expression expr;
  p4::v1::TableEntry entry;
  EXPECT_THAT(EntryMeetsConstraint(entry, MakeConstraintInfo(expr)),
              StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(EntryMeetsConstraintTest, BooleanConstants) {
  p4::v1::TableEntry entry;
  auto const_true = ExpressionWithType(kBool, "boolean_constant: true");
  auto const_false = ExpressionWithType(kBool, "boolean_constant: false");
  EXPECT_THAT(EntryMeetsConstraint(entry, MakeConstraintInfo(const_true)),
              IsOkAndHolds(Eq(true)));
  EXPECT_THAT(EntryMeetsConstraint(entry, MakeConstraintInfo(const_false)),
              IsOkAndHolds(Eq(false)));
}

TEST_F(EntryMeetsConstraintTest, NonBooleanConstraintsAreRejected) {
  p4::v1::TableEntry entry;
  for (const Type& type : {kArbitraryInt, kFixedUnsigned16, kFixedUnsigned32}) {
    auto expr = ExpressionWithType(type, R"(integer_constant: "42")");
    EXPECT_THAT(EntryMeetsConstraint(entry, MakeConstraintInfo(expr)),
                StatusIs(StatusCode::kInvalidArgument));
  }

  // Expressions evaluating to non-scalar values should also be rejected.
  for (std::string key : {"exact32", "ternary32", "lpm32", "range32"}) {
    EXPECT_THAT(EntryMeetsConstraint(entry, MakeConstraintInfo(KeyExpr(key))),
                StatusIs(StatusCode::kInvalidArgument));
  }
}

TEST_F(EvalTest, IntegerConstant) {
  for (auto int_str :
       {"0", "-1", "1", "42", "-9042852073498123679518173785123857"}) {
    for (const Type& type :
         {kArbitraryInt, kFixedUnsigned16, kFixedUnsigned32}) {
      auto expr = ExpressionWithType(
          type, absl::Substitute(R"(integer_constant: "$0")", int_str));
      EvalResult result = mpz_class(int_str);
      EXPECT_THAT(Eval(expr, TableEntry{}), IsOkAndHolds(Eq(result)));
    }
  }
}

TEST_F(EvalTest, Key) {
  for (auto& name_and_key_info : kTableInfo.keys_by_name) {
    auto key_name = name_and_key_info.first;
    auto expr = KeyExpr(key_name);
    EvalResult result = kParsedEntry.keys.find(key_name)->second;
    if (expr.type().type_case() == Type::kUnknown ||
        expr.type().type_case() == Type::kUnsupported) {
      EXPECT_THAT(Eval(expr, kParsedEntry), StatusIs(StatusCode::kInternal));
    } else {
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));
    }
  }
}

TEST_F(EvalTest, BooleanNegation) {
  for (bool boolean : {true, false}) {
    auto inner_expr = ExpressionWithType(
        kBool, absl::Substitute("boolean_constant: $0", boolean));
    for (int i = 0; i < 4; i++) {
      auto expr = ExpressionWithType(kBool, "");
      *expr.mutable_boolean_negation() = inner_expr;
      EvalResult result = (i % 2 == 0) ? (!boolean) : boolean;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));
      inner_expr = expr;
    }
  }
}

TEST_F(EvalTest, ArithmeticNegation) {
  Integer value = mpz_class(42);
  auto inner_expr =
      ExpressionWithType(kArbitraryInt, R"(integer_constant: "42")");
  for (int i = 0; i < 4; i++) {
    auto expr = ExpressionWithType(kArbitraryInt, "");
    *expr.mutable_arithmetic_negation() = inner_expr;
    EvalResult result = (i % 2 == 0) ? (0 - value) : value;
    EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));
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
    ASSERT_THAT(Eval(fixed32, kParsedEntry), IsOkAndHolds(Eq(result)));

    Expression expr = ExpressionWithType(kExact32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Exact{.value = unsigned_n};
    EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

    expr = ExpressionWithType(kTernary32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Ternary{.value = unsigned_n, .mask = max_uint32};
    EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

    expr = ExpressionWithType(kLpm32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Lpm{.value = unsigned_n, .prefix_length = 32};
    EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

    expr = ExpressionWithType(kRange32, "");
    *expr.mutable_type_cast() = fixed32;
    result = Range{.low = unsigned_n, .high = unsigned_n};
    EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));
  }
}

TEST_F(EvalTest, BinaryExpression_BooleanArguments) {
  const auto const_true = ExpressionWithType(kBool, "boolean_constant: true");
  const auto const_false = ExpressionWithType(kBool, "boolean_constant: false");
  auto boolean = [&](bool boolean) -> Expression {
    return boolean ? const_true : const_false;
  };

  for (bool left : {true, false}) {
    for (bool right : {true, false}) {
      auto expr = ExpressionWithType(
          kBool, absl::Substitute("binary_expression { left {$0} right {$1} }",
                                  boolean(left).DebugString(),
                                  boolean(right).DebugString()));
      EvalResult result;

      expr.mutable_binary_expression()->set_binop(ast::AND);
      result = left && right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::OR);
      result = left || right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::IMPLIES);
      result = !left || right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::EQ);
      result = left == right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::NE);
      result = left != right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      for (auto comparison : {ast::GT, ast::GE, ast::LT, ast::LE}) {
        expr.mutable_binary_expression()->set_binop(comparison);
        EXPECT_THAT(Eval(expr, kParsedEntry), StatusIs(StatusCode::kInternal));
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
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::NE);
      result = left != right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::GT);
      result = left > right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::GE);
      result = left >= right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::LT);
      result = left < right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      expr.mutable_binary_expression()->set_binop(ast::LE);
      result = left <= right;
      EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

      for (auto boolean_op : {ast::AND, ast::OR, ast::IMPLIES}) {
        expr.mutable_binary_expression()->set_binop(boolean_op);
        EXPECT_THAT(Eval(expr, kParsedEntry), StatusIs(StatusCode::kInternal));
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
    EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

    expr.mutable_binary_expression()->set_binop(ast::NE);
    result = false;
    EXPECT_THAT(Eval(expr, kParsedEntry), IsOkAndHolds(Eq(result)));

    for (auto binop : {ast::GT, ast::GE, ast::LT, ast::LE, ast::AND, ast::OR,
                       ast::IMPLIES}) {
      expr.mutable_binary_expression()->set_binop(binop);
      EXPECT_THAT(Eval(expr, kParsedEntry), StatusIs(StatusCode::kInternal));
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
  EXPECT_THAT(
      Eval(FieldAccessExpr("value", "exact32", kFixedUnsigned32), entry),
      IsOkAndHolds(Eq(result)));
  for (std::string bad_field : {"mask", "prefix_length", "low", "high", "xy"}) {
    EXPECT_THAT(
        Eval(FieldAccessExpr(bad_field, "exact32", kFixedUnsigned32), entry),
        StatusIs(StatusCode::kInternal));
  }

  entry = kParsedEntry;  // Reset.
  entry.keys["ternary32"] = Ternary{.value = value, .mask = value2};
  EXPECT_THAT(
      Eval(FieldAccessExpr("value", "ternary32", kFixedUnsigned32), entry),
      IsOkAndHolds(Eq(result)));
  EXPECT_THAT(
      Eval(FieldAccessExpr("mask", "ternary32", kFixedUnsigned32), entry),
      IsOkAndHolds(Eq(result2)));
  for (std::string bad_field : {"prefix_length", "low", "high", "xy", "foo"}) {
    EXPECT_THAT(
        Eval(FieldAccessExpr(bad_field, "ternary32", kFixedUnsigned32), entry),
        StatusIs(StatusCode::kInternal));
  }

  entry = kParsedEntry;  // Reset.
  entry.keys["lpm32"] = Lpm{.value = value, .prefix_length = value2};
  EXPECT_THAT(Eval(FieldAccessExpr("value", "lpm32", kFixedUnsigned32), entry),
              IsOkAndHolds(Eq(result)));
  EXPECT_THAT(
      Eval(FieldAccessExpr("prefix_length", "lpm32", kFixedUnsigned32), entry),
      IsOkAndHolds(Eq(result2)));
  for (std::string bad_field : {"mask", "low", "high", "xy", "foo", "bar"}) {
    EXPECT_THAT(
        Eval(FieldAccessExpr(bad_field, "lpm32", kFixedUnsigned32), entry),
        StatusIs(StatusCode::kInternal));
  }

  entry = kParsedEntry;  // Reset.
  entry.keys["range32"] = Range{.low = value, .high = value2};
  EXPECT_THAT(Eval(FieldAccessExpr("low", "range32", kFixedUnsigned32), entry),
              IsOkAndHolds(Eq(result)));
  EXPECT_THAT(Eval(FieldAccessExpr("high", "range32", kFixedUnsigned32), entry),
              IsOkAndHolds(Eq(result2)));
  for (std::string bad_field : {"value", "mask", "prefix_length", "xy", "fo"}) {
    EXPECT_THAT(
        Eval(FieldAccessExpr(bad_field, "range32", kFixedUnsigned32), entry),
        StatusIs(StatusCode::kInternal));
  }
}

}  // namespace internal_interpreter
}  // namespace p4_constraints
