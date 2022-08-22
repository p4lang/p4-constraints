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

#include "p4_constraints/backend/type_checker.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/substitute.h"
#include "gutils/parse_text_proto.h"
#include "gutils/status_matchers.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/constraint_source.h"

namespace p4_constraints {

using ::absl::StatusCode;
using ::gutils::ParseTextProtoOrDie;
using ::gutils::testing::status::IsOk;
using ::gutils::testing::status::StatusIs;
using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::Type;

class InferAndCheckTypesTest : public ::testing::Test {
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

  const ast::SourceLocation kMockLocation =
      ParseTextProtoOrDie<ast::SourceLocation>(R"pb(file_path: "Mock")pb");

  const TableInfo kTableInfo{
      0,
      "table",
      {},
      // For the purpose of testing, quoting is not important.
      ConstraintSource{
          .constraint_string = " ",
          .constraint_location = kMockLocation,
      },
      {},
      {
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

  // Required by negative tests to avoid internal quoting errors.
  void AddMockSourceLocations(Expression& expr) {
    *expr.mutable_start_location() = kMockLocation;
    *expr.mutable_end_location() = kMockLocation;
    switch (expr.expression_case()) {
      case ast::Expression::kBooleanConstant:
      case ast::Expression::kIntegerConstant:
      case ast::Expression::kKey:
      case ast::Expression::kMetadataAccess:
      case ast::Expression::EXPRESSION_NOT_SET:
        return;
      case ast::Expression::kBinaryExpression:
        AddMockSourceLocations(
            *expr.mutable_binary_expression()->mutable_left());
        AddMockSourceLocations(
            *expr.mutable_binary_expression()->mutable_right());
        return;
      case ast::Expression::kBooleanNegation:
        AddMockSourceLocations(*expr.mutable_boolean_negation());
        return;
      case ast::Expression::kTypeCast:
        AddMockSourceLocations(*expr.mutable_type_cast());
        return;
      case ast::Expression::kArithmeticNegation:
        AddMockSourceLocations(*expr.mutable_arithmetic_negation());
        return;
      case ast::Expression::kFieldAccess:
        AddMockSourceLocations(*expr.mutable_field_access()->mutable_expr());
    }
  }
};

TEST_F(InferAndCheckTypesTest, InvalidExpressions) {
  Expression expr = ParseTextProtoOrDie<Expression>("");
  AddMockSourceLocations(expr);
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
              StatusIs(StatusCode::kInvalidArgument));

  expr = ParseTextProtoOrDie<Expression>("boolean_negation {}");
  AddMockSourceLocations(expr);
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
              StatusIs(StatusCode::kInvalidArgument));

  expr = ParseTextProtoOrDie<Expression>("type_cast {}");
  AddMockSourceLocations(expr);
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
              StatusIs(StatusCode::kInvalidArgument));

  expr = ParseTextProtoOrDie<Expression>("binary_expression {}");
  AddMockSourceLocations(expr);
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
              StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(InferAndCheckTypesTest, BooleanConstant) {
  Expression expr = ParseTextProtoOrDie<Expression>("boolean_constant: true");
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
  EXPECT_TRUE(expr.type().has_boolean());

  expr = ParseTextProtoOrDie<Expression>("boolean_constant: false");
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
  EXPECT_TRUE(expr.type().has_boolean());
}

TEST_F(InferAndCheckTypesTest, IntegerConstant) {
  Expression expr =
      ParseTextProtoOrDie<Expression>(R"pb(integer_constant: "123")pb");
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
  EXPECT_TRUE(expr.type().has_arbitrary_int());
}

TEST_F(InferAndCheckTypesTest, KnownVariablesTypeCheck) {
  std::pair<std::string, Type> key_type_pairs[] = {
      {"bool", kBool},
      {"int", kArbitraryInt},
      {"bit32", kFixedUnsigned32},
      {"exact32", kExact32},
      {"ternary32", kTernary32},
      {"lpm32", kLpm32},
      {"range32", kRange32},
  };
  for (auto& key_type_pair : key_type_pairs) {
    Expression expr = ParseTextProtoOrDie<Expression>(
        absl::Substitute(R"( key: "$0" )", key_type_pair.first));
    ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
    EXPECT_TRUE(expr.type() == key_type_pair.second);
  }
}

TEST_F(InferAndCheckTypesTest, UnknownVariablesDontTypeCheck) {
  std::string keys[] = {"unknown", "unsupported", "not even a key"};
  for (auto& key : keys) {
    Expression expr = ParseTextProtoOrDie<Expression>(
        absl::Substitute(R"( key: "$0" )", key));
    AddMockSourceLocations(expr);
    EXPECT_THAT(InferAndCheckTypes(&expr, kTableInfo),
                StatusIs(StatusCode::kInvalidArgument));
  }
}

TEST_F(InferAndCheckTypesTest, BooleanNegationOfBooleansTypeChecks) {
  Expression expr = ParseTextProtoOrDie<Expression>(R"pb(
    boolean_negation { boolean_constant: true }
  )pb");
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
  EXPECT_TRUE(expr.type().has_boolean());

  // Double negation.
  expr = ParseTextProtoOrDie<Expression>(R"pb(
    boolean_negation { boolean_negation { boolean_constant: false } }
  )pb");
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
  EXPECT_TRUE(expr.type().has_boolean());

  // Boolean key.
  expr = ParseTextProtoOrDie<Expression>(
      R"pb(boolean_negation { key: "bool" })pb");
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
  EXPECT_TRUE(expr.type().has_boolean());
}

TEST_F(InferAndCheckTypesTest, BooleanNegationOfNonBooleansDoesNotTypeCheck) {
  Expression expr = ParseTextProtoOrDie<Expression>("boolean_negation {}");
  AddMockSourceLocations(expr);
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
              StatusIs(StatusCode::kInvalidArgument));

  expr = ParseTextProtoOrDie<Expression>(R"pb(
    boolean_negation { integer_constant: "0" }
  )pb");
  AddMockSourceLocations(expr);
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
              StatusIs(StatusCode::kInvalidArgument));

  for (std::string key : {"unknown", "unsupported", "int", "bit32", "exact32",
                          "ternary32", "lpm32", "range32"}) {
    Expression expr = ParseTextProtoOrDie<Expression>(
        absl::Substitute(R"(boolean_negation { key: "$0" })", key));
    AddMockSourceLocations(expr);
    ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
                StatusIs(StatusCode::kInvalidArgument))
        << "cannot negate key " << key;
  }
}

TEST_F(InferAndCheckTypesTest, ArithmeticNegationOfIntTypeChecks) {
  Expression expr = ParseTextProtoOrDie<Expression>(R"pb(
    arithmetic_negation { integer_constant: "0" }
  )pb");
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
  EXPECT_TRUE(expr.type().has_arbitrary_int());

  // Double negation.
  expr = ParseTextProtoOrDie<Expression>(R"pb(
    arithmetic_negation { arithmetic_negation { integer_constant: "1" } }
  )pb");
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
  EXPECT_TRUE(expr.type().has_arbitrary_int());

  // Arithmetic negation of int key.
  expr = ParseTextProtoOrDie<Expression>(
      R"pb(arithmetic_negation { key: "int" })pb");
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
  EXPECT_TRUE(expr.type().has_arbitrary_int());
}

TEST_F(InferAndCheckTypesTest, ArithmeticNegationOfNonIntDoesNotTypeChecks) {
  Expression expr = ParseTextProtoOrDie<Expression>("arithmetic_negation {}");
  AddMockSourceLocations(expr);
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
              StatusIs(StatusCode::kInvalidArgument));

  expr = ParseTextProtoOrDie<Expression>(R"pb(
    arithmetic_negation { boolean_constant: true }
  )pb");
  AddMockSourceLocations(expr);
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
              StatusIs(StatusCode::kInvalidArgument));

  for (std::string key : {"unknown", "unsupported", "bool", "bit32", "exact32",
                          "ternary32", "lpm32", "range32"}) {
    expr = ParseTextProtoOrDie<Expression>(
        absl::Substitute(R"(arithmetic_negation { key: "$0" })", key));
    AddMockSourceLocations(expr);
    ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
                StatusIs(StatusCode::kInvalidArgument))
        << "cannot negate key " << key;
  }
}

TEST_F(InferAndCheckTypesTest, TypeCastNeverTypeChecks) {
  // TypeCasts should only be inserted by the type checker, so preexisting
  // TypeCasts should be rejected.
  Expression expr = ParseTextProtoOrDie<Expression>(
      R"pb(type_cast { integer_constant: "0" })pb");
  AddMockSourceLocations(expr);
  ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
              StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(InferAndCheckTypesTest, LegalTypeCastEqualityComparisonTypeChecks) {
  const std::pair<std::string, std::string> castable_pairs[] = {
      {"int", "bit16"},       {"int", "exact32"}, {"int", "ternary32"},
      {"int", "lpm32"},       {"int", "range32"}, {"bit32", "exact32"},
      {"bit32", "ternary32"}, {"bit32", "lpm32"}, {"bit32", "range32"}};
  for (ast::BinaryOperator op : {ast::EQ, ast::NE}) {
    // expr.mutable_binary_expression()->set_binop(op);
    for (std::pair<std::string, std::string> left_right : castable_pairs) {
      Expression expr = ParseTextProtoOrDie<Expression>(
          absl::Substitute(R"pb(
                             binary_expression {
                               binop: $0
                               left { key: "$1" }
                               right { key: "$2" }
                             })pb",
                           op, left_right.first, left_right.second));
      ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk())
          << expr.DebugString();
      EXPECT_TRUE(expr.binary_expression().left().has_type_cast())
          << expr.DebugString();
      ASSERT_EQ(expr.binary_expression().left().type().type_case(),
                expr.binary_expression().right().type().type_case())
          << expr.DebugString();
      EXPECT_TRUE(expr.binary_expression().left().type() ==
                  expr.binary_expression().right().type())
          << expr.DebugString();
    }
  }
}

TEST_F(InferAndCheckTypesTest, IllegalTypeCastEqualityComparisonFails) {
  const std::pair<std::string, std::string> uncastable_pairs[] = {
      {"bool", "int"},        {"bool", "bit32"},    {"bool", "exact32"},
      {"bool", "ternary32"},  {"bool", "lpm32"},    {"bool", "range32"},
      {"bit16", "bit32"},     {"bit16", "exact32"}, {"bit16", "ternary32"},
      {"bit16", "lpm32"},     {"bit16", "range32"}, {"exact32", "ternary32"},
      {"ternary32", "lpm32"}, {"lpm32", "range32"}};
  for (ast::BinaryOperator op : {ast::EQ, ast::NE}) {
    for (std::pair<std::string, std::string> left_right : uncastable_pairs) {
      Expression expr = ParseTextProtoOrDie<Expression>(
          absl::Substitute(R"pb(
                             binary_expression {
                               binop: $0
                               left { key: "$1" }
                               right { key: "$2" }
                             })pb",
                           op, left_right.first, left_right.second));
      AddMockSourceLocations(expr);
      EXPECT_THAT(InferAndCheckTypes(&expr, kTableInfo),
                  StatusIs(StatusCode::kInvalidArgument))
          << expr.DebugString();
    }
  }
}

TEST_F(InferAndCheckTypesTest, BinaryBooleanOperators) {
  for (ast::BinaryOperator op : {ast::AND, ast::OR, ast::IMPLIES}) {
    // Positive tests.
    Expression expr = ParseTextProtoOrDie<Expression>(
        absl::Substitute(R"pb(
                           binary_expression {
                             binop: $0
                             left { key: "bool" }
                             right { boolean_constant: false }
                           })pb",
                         op));
    ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk());
    EXPECT_TRUE(expr.type().has_boolean());

    Expression nested = ParseTextProtoOrDie<Expression>(
        absl::Substitute(R"pb(
                           binary_expression {
                             binop: $0
                             left { $1 }
                             right { $1 }
                           })pb",
                         op, expr.DebugString()));
    Expression* right = expr.mutable_binary_expression()->mutable_right();
    std::swap(*right->mutable_binary_expression()->mutable_left(),
              *right->mutable_binary_expression()->mutable_right());
    ASSERT_THAT(InferAndCheckTypes(&nested, kTableInfo), IsOk());
    EXPECT_TRUE(nested.type().has_boolean());

    // Negative tests.
    nested.mutable_binary_expression()->set_binop(ast::UNKNOWN_OPERATOR);
    ASSERT_THAT(InferAndCheckTypes(&nested, kTableInfo),
                StatusIs(StatusCode::kInternal));
    nested.mutable_binary_expression()->set_binop(op);
    for (std::string key :
         {"int", "bit32", "exact32", "ternary32", "lpm32", "range32"}) {
      *expr.mutable_binary_expression()->mutable_right()->mutable_key() = key;
      AddMockSourceLocations(expr);
      ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
                  StatusIs(StatusCode::kInvalidArgument));

      *nested.mutable_binary_expression()->mutable_right() = expr;
      AddMockSourceLocations(nested);
      ASSERT_THAT(InferAndCheckTypes(&nested, kTableInfo),
                  StatusIs(StatusCode::kInvalidArgument));
    }
  }
}

TEST_F(InferAndCheckTypesTest, OrderedComparisonOperatorsFails) {
  for (ast::BinaryOperator op : {ast::GT, ast::GE, ast::LT, ast::LE}) {
    for (std::string key : {"bool", "ternary32", "lpm32", "range32"}) {
      Expression expr = ParseTextProtoOrDie<Expression>(
          absl::Substitute(R"pb(
                             binary_expression {
                               binop: $0
                               left { key: "$1" }
                               right { key: "$1" }
                             })pb",
                           op, key));
      AddMockSourceLocations(expr);
      ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo),
                  StatusIs(StatusCode::kInvalidArgument))
          << expr.DebugString();
    }
  }
}

TEST_F(InferAndCheckTypesTest, OrderedComparisonOperatorsTypeChecks) {
  for (ast::BinaryOperator op : {ast::GT, ast::GE, ast::LT, ast::LE}) {
    for (std::string key : {"int", "bit16", "exact32"}) {
      Expression expr = ParseTextProtoOrDie<Expression>(
          absl::Substitute(R"pb(
                             binary_expression {
                               binop: $0
                               left { key: "$1" }
                               right { key: "$1" }
                             })pb",
                           op, key));
      ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk())
          << expr.DebugString();
      EXPECT_TRUE(expr.type().has_boolean()) << expr.DebugString();
    }
  }
}

TEST_F(InferAndCheckTypesTest, FieldAccessTypeChecks) {
  using Fields = std::vector<std::pair<std::string, Type>>;
  const std::pair<std::string, Fields> test_cases[] = {
      {"exact32", {{"value", kFixedUnsigned32}}},
      {"ternary32", {{"value", kFixedUnsigned32}, {"mask", kFixedUnsigned32}}},
      {"lpm32",
       {{"value", kFixedUnsigned32}, {"prefix_length", kArbitraryInt}}},
      {"range32", {{"low", kFixedUnsigned32}, {"high", kFixedUnsigned32}}},
  };
  for (auto& test_case : test_cases) {
    auto& key = test_case.first;
    auto& fields = test_case.second;
    for (auto& field_and_type : fields) {
      auto& field = field_and_type.first;
      auto& field_type = field_and_type.second;
      Expression expr = ParseTextProtoOrDie<Expression>(
          absl::Substitute(R"pb(
                             field_access {
                               field: "$0"
                               expr { key: "$1" }
                             })pb",
                           field, key));
      ASSERT_THAT(InferAndCheckTypes(&expr, kTableInfo), IsOk())
          << expr.DebugString();
      EXPECT_EQ(expr.type(), field_type) << expr.DebugString();
    }
  }
}

TEST_F(InferAndCheckTypesTest, FieldAccess_AccessNonExistingField) {
  using TestCase = std::pair<std::string, std::vector<std::string>>;
  const TestCase test_cases[] = {
      {"exact32", {"mask", "prefix_length", "low", "high", "foo", "bar"}},
      {"ternary32", {"prefix_length", "low", "high", "foo", "bar"}},
      {"lpm32", {"mask", "low", "high", "foo", "bar"}},
      {"range32", {"mask", "prefix_length", "foo", "bar"}},
  };
  for (auto& test_case : test_cases) {
    auto& key = test_case.first;
    auto& illegal_fields = test_case.second;
    for (auto& field : illegal_fields) {
      Expression expr = ParseTextProtoOrDie<Expression>(
          absl::Substitute(R"pb(
                             field_access {
                               field: "$0"
                               expr { key: "$1" }
                             })pb",
                           field, key));
      AddMockSourceLocations(expr);
      EXPECT_THAT(InferAndCheckTypes(&expr, kTableInfo),
                  StatusIs(StatusCode::kInvalidArgument))
          << expr.DebugString();
    }
  }
}

TEST_F(InferAndCheckTypesTest, FieldAccess_AccessFieldOfScalarExpression) {
  const std::string keys_with_scalar_types[] = {
      "unknown", "unsupported", "bool", "int", "bit16", "bit32"};
  const std::string fields[] = {"value", "mask", "prefix_length", "low", "high",
                                "foo",   "bar"};
  for (auto& key : keys_with_scalar_types) {
    for (auto& field : fields) {
      Expression expr = ParseTextProtoOrDie<Expression>(
          absl::Substitute(R"pb(
                             field_access {
                               field: "$0"
                               expr { key: "$1" }
                             })pb",
                           field, key));
      AddMockSourceLocations(expr);
      EXPECT_THAT(InferAndCheckTypes(&expr, kTableInfo),
                  StatusIs(StatusCode::kInvalidArgument))
          << expr.DebugString();
    }
  }
}

TEST_F(InferAndCheckTypesTest, MetadataAccessTypeChecks) {
  Expression expr = ParseTextProtoOrDie<Expression>(R"pb(
    metadata_access { metadata_name: "priority" }
  )pb");
  ASSERT_OK(InferAndCheckTypes(&expr, kTableInfo)) << expr.DebugString();
  EXPECT_EQ(expr.type(), kArbitraryInt) << expr.DebugString();
}

}  // namespace p4_constraints
