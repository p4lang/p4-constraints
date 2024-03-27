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
using ::testing::Not;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

std::string PrintTextProto(const google::protobuf::Message& message) {
  std::string text;
  google::protobuf::TextFormat::PrintToString(message, &text);
  return text;
}

class ReasonEntryViolatesConstraintTest : public ::testing::Test {
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
  const ConstraintSource kDummySource = {
      .constraint_string = "source",
      .constraint_location = ast::SourceLocation(),
  };

  const TableInfo kTableInfo = {
      .id = 1,
      .name = "table",
      .constraint = {},  // To be filled in later.
      .keys_by_id =
          {
              {1, {1, "exact32", kExact32}}
              // For testing purposes, fine to omit the other keys here.
          },
      .keys_by_name = {
          {"exact32", {1, "exact32", kExact32}},
          {"ternary32", {2, "ternary32", kTernary32}},
          {"lpm32", {3, "lpm32", kLpm32}},
          {"range32", {4, "range32", kRange32}},
          {"optional32", {5, "optional32", kOptional32}},
      }};

  const TableEntry kParsedEntry = {
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

  const EvaluationContext kEvaluationContext = {
      .constraint_context = kParsedEntry,
      .constraint_source = kDummySource,
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
    return {
        .action_info_by_id = {},
        .table_info_by_id = {{table_info.id, table_info}},
    };
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
        .constraint_context = entry,
        .constraint_source = kDummySource,
    };
  }

  // Constraint to check that multicast_group_id != 0.
  const Expression kMulticastGroupIdConstraint = ExpressionWithType(kBool, R"pb(
    binary_expression {
      binop: NE
      left {
        type { fixed_unsigned { bitwidth: 32 } }
        action_parameter: "multicast_group_id"
      }
      right {
        type { fixed_unsigned { bitwidth: 32 } }
        type_cast {
          type { arbitrary_int {} }
          integer_constant: "0"
        }
      }
    }
  )pb");

  // Constraint to check that vlan_id != 0.
  const Expression kVlanIdConstraint = ExpressionWithType(kBool, R"pb(
    binary_expression {
      binop: NE
      left {
        type { fixed_unsigned { bitwidth: 32 } }
        action_parameter: "vlan_id"
      }
      right {
        type { fixed_unsigned { bitwidth: 32 } }
        type_cast {
          type { arbitrary_int {} }
          integer_constant: "0"
        }
      }
    }
  )pb");

  const ActionInfo kMulticastGroupIdActionInfo = {
      .id = 123,
      .name = "multicast_group_id",
      .constraint = kMulticastGroupIdConstraint,
      .params_by_id = {{1, {1, "multicast_group_id", kFixedUnsigned32}}},
      .params_by_name = {{"multicast_group_id",
                          {1, "multicast_group_id", kFixedUnsigned32}}},
  };

  const ActionInfo kActionInfoVlanId = {
      .id = 124,
      .name = "vlan_id",
      .constraint = kVlanIdConstraint,
      .params_by_id = {{1, {1, "vlan_id", kFixedUnsigned32}}},
      .params_by_name = {{"vlan_id", {1, "vlan_id", kFixedUnsigned32}}},
  };
};

class EvalTest : public ReasonEntryViolatesConstraintTest {};
class EvalToBoolCacheTest : public ReasonEntryViolatesConstraintTest {};

TEST_F(ReasonEntryViolatesConstraintTest, EntryShouldMeetActionConstraint) {
  p4::v1::TableEntry table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
    table_id: 1
    action {
      action {
        action_id: 123
        params { param_id: 1 value: "\x6" }
      }
    }
  )pb");

  const ConstraintInfo constraint_info = {
      .action_info_by_id = {{kMulticastGroupIdActionInfo.id,
                             kMulticastGroupIdActionInfo}},
      .table_info_by_id = {{kTableInfo.id, kTableInfo}},
  };

  ASSERT_THAT(ReasonEntryViolatesConstraint(table_entry, constraint_info),
              IsOkAndHolds(Eq("")));
}

TEST_F(ReasonEntryViolatesConstraintTest, MissingActionIdShouldFailForAction) {
  p4::v1::TableEntry table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
    table_id: 1
    action {
      action {
        action_id: 123
        params { param_id: 1 value: "\x0" }
      }
    }
  )pb");

  const ConstraintInfo constraint_info = {
      .action_info_by_id = {},
      .table_info_by_id = {{kTableInfo.id, kTableInfo}},
  };
  ASSERT_THAT(ReasonEntryViolatesConstraint(table_entry, constraint_info),
              StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(ReasonEntryViolatesConstraintTest,
       MissingActionIdShouldFailForActionProfileActionSet) {
  p4::v1::TableEntry table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
    table_id: 1
    action {
      action_profile_action_set {
        action_profile_actions {
          action {
            action_id: 123
            params { param_id: 1 value: "\x6" }
          }
          weight: 1
        }
        action_profile_actions {
          action {
            action_id: 124
            params { param_id: 1 value: "\x6" }
          }
          weight: 2
        }
      }
    }
  )pb");

  const ConstraintInfo constraint_info = {
      .action_info_by_id = {{1,  // No action with action_id of 1.
                             kMulticastGroupIdActionInfo},
                            {2,  // No action with action_id of 2.
                             kActionInfoVlanId}},
      .table_info_by_id = {{kTableInfo.id, kTableInfo}},
  };
  ASSERT_THAT(ReasonEntryViolatesConstraint(table_entry, constraint_info),
              StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(ReasonEntryViolatesConstraintTest,
       ActionProfileMemberIdReturnsUnimplementedError) {
  p4::v1::TableEntry table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
    table_id: 1
    action { action_profile_member_id: 1 }
  )pb");

  const ConstraintInfo constraint_info = {
      .action_info_by_id = {{kMulticastGroupIdActionInfo.id,
                             kMulticastGroupIdActionInfo}},
      .table_info_by_id = {{kTableInfo.id, kTableInfo}},
  };
  ASSERT_THAT(ReasonEntryViolatesConstraint(table_entry, constraint_info),
              StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(ReasonEntryViolatesConstraintTest,
       ActionProfileGroupIdReturnsUnimplementedError) {
  p4::v1::TableEntry table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
    table_id: 1
    action { action_profile_group_id: 1 }
  )pb");

  const ConstraintInfo constraint_info = {
      .action_info_by_id = {{kMulticastGroupIdActionInfo.id,
                             kMulticastGroupIdActionInfo}},
      .table_info_by_id = {{kTableInfo.id, kTableInfo}},
  };
  ASSERT_THAT(ReasonEntryViolatesConstraint(table_entry, constraint_info),
              StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(ReasonEntryViolatesConstraintTest, EntryShouldViolateActionConstraint) {
  p4::v1::TableEntry table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
    table_id: 1
    action {
      action {
        action_id: 123
        params { param_id: 1 value: "\x0" }
      }
    }
  )pb");

  // Constraint to check that multicast_group_id != 0.
  Expression multicast_group_id_constraint =
      ParseTextProtoOrDie<Expression>(R"pb(
        start_location { action_name: "multicast_group_id" }
        end_location { action_name: "multicast_group_id" }
        type { boolean {} }
        binary_expression {
          binop: NE
          left {
            type { fixed_unsigned { bitwidth: 32 } }
            action_parameter: "multicast_group_id"
          }
          right {
            type { fixed_unsigned { bitwidth: 32 } }
            type_cast {
              type { arbitrary_int {} }
              integer_constant: "0"
            }
          }
        }
      )pb");

  ActionInfo action_info = kMulticastGroupIdActionInfo;
  action_info.constraint = multicast_group_id_constraint;
  action_info.constraint_source.constraint_location.set_action_name(
      "multicast_group_id");

  const ConstraintInfo constraint_info = {
      .action_info_by_id = {{action_info.id, action_info}},
      .table_info_by_id = {{kTableInfo.id, kTableInfo}},
  };
  ASSERT_THAT(ReasonEntryViolatesConstraint(table_entry, constraint_info),
              IsOkAndHolds(Not(Eq(""))));
}

TEST_F(ReasonEntryViolatesConstraintTest,
       EntryShouldMeetActionProfileActionSetConstraint) {
  p4::v1::TableEntry table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
    table_id: 1
    action {
      action_profile_action_set {
        action_profile_actions {
          action {
            action_id: 123
            params { param_id: 1 value: "\x6" }
          }
          weight: 1
        }
        action_profile_actions {
          action {
            action_id: 124
            params { param_id: 1 value: "\x6" }
          }
          weight: 2
        }
      }
    }
  )pb");

  const ConstraintInfo constraint_info = {
      .action_info_by_id = {{kMulticastGroupIdActionInfo.id,
                             kMulticastGroupIdActionInfo},
                            {kActionInfoVlanId.id, kActionInfoVlanId}},
      .table_info_by_id = {{kTableInfo.id, kTableInfo}},
  };

  ASSERT_THAT(ReasonEntryViolatesConstraint(table_entry, constraint_info),
              IsOkAndHolds(Eq("")));
}

TEST_F(ReasonEntryViolatesConstraintTest,
       EntryShouldViolateActionProfileActionSetConstraint) {
  p4::v1::TableEntry table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
    table_id: 1
    action {
      action_profile_action_set {
        action_profile_actions {
          action {
            action_id: 123
            params { param_id: 1 value: "\x6" }
          }
          weight: 1
        }
        action_profile_actions {
          action {
            action_id: 124
            params { param_id: 1 value: "\x0" }
          }
          weight: 2
        }
      }
    }
  )pb");

  // Constraint to check that multicast_group_id != 0.
  Expression multicast_group_id_constraint =
      ParseTextProtoOrDie<Expression>(R"pb(
        start_location { action_name: "multicast_group_id" }
        end_location { action_name: "multicast_group_id" }
        type { boolean {} }
        binary_expression {
          binop: NE
          left {
            type { fixed_unsigned { bitwidth: 32 } }
            action_parameter: "multicast_group_id"
          }
          right {
            type { fixed_unsigned { bitwidth: 32 } }
            type_cast {
              type { arbitrary_int {} }
              integer_constant: "0"
            }
          }
        }
      )pb");

  // Constraint to check that vlan_id != 0.
  Expression vlan_id_constraint = ParseTextProtoOrDie<Expression>(R"pb(
    start_location { action_name: "vlan_id" }
    end_location { action_name: "vlan_id" }
    type { boolean {} }
    binary_expression {
      binop: NE
      left {
        type { fixed_unsigned { bitwidth: 32 } }
        action_parameter: "vlan_id"
      }
      right {
        type { fixed_unsigned { bitwidth: 32 } }
        type_cast {
          type { arbitrary_int {} }
          integer_constant: "0"
        }
      }
    }
  )pb");

  ActionInfo multicast_group_id_action_info = kMulticastGroupIdActionInfo;
  ActionInfo vlan_id_action_info = kActionInfoVlanId;

  multicast_group_id_action_info.constraint = multicast_group_id_constraint;
  multicast_group_id_action_info.constraint_source.constraint_location
      .set_action_name("multicast_group_id");

  vlan_id_action_info.constraint = vlan_id_constraint;
  vlan_id_action_info.constraint_source.constraint_location.set_action_name(
      "vlan_id");

  const ConstraintInfo constraint_info = {
      .action_info_by_id = {{multicast_group_id_action_info.id,
                             multicast_group_id_action_info},
                            {vlan_id_action_info.id, vlan_id_action_info}},
      .table_info_by_id = {{kTableInfo.id, kTableInfo}},
  };

  ASSERT_THAT(ReasonEntryViolatesConstraint(table_entry, constraint_info),
              IsOkAndHolds(Not(Eq(""))));
}

TEST_F(ReasonEntryViolatesConstraintTest, EmptyExpressionErrors) {
  const Expression kExpr;
  EXPECT_THAT(
      ReasonEntryViolatesConstraint(kTableEntry, MakeConstraintInfo(kExpr)),
      StatusIs(StatusCode::kInvalidArgument));
}

TEST_F(ReasonEntryViolatesConstraintTest, BooleanConstants) {
  const Expression kConstTrue =
      ExpressionWithType(kBool, "boolean_constant: true");

  // start_location and end_location provided for quoting.
  Expression const_false = ParseTextProtoOrDie<Expression>(R"pb(
    start_location { table_name: "table" }
    end_location { table_name: "table" }
    type { boolean {} }
    boolean_constant: false
  )pb");

  EXPECT_THAT(ReasonEntryViolatesConstraint(kTableEntry,
                                            MakeConstraintInfo(kConstTrue)),
              IsOkAndHolds(Eq("")));
  EXPECT_THAT(ReasonEntryViolatesConstraint(kTableEntry,
                                            MakeConstraintInfo(const_false)),
              IsOkAndHolds(Not(Eq(""))));
}

TEST_F(ReasonEntryViolatesConstraintTest, NonBooleanConstraintsAreRejected) {
  for (const Type& type : {kArbitraryInt, kFixedUnsigned16, kFixedUnsigned32}) {
    const Expression kExpr =
        ExpressionWithType(type, R"(integer_constant: "42")");
    EXPECT_THAT(
        ReasonEntryViolatesConstraint(kTableEntry, MakeConstraintInfo(kExpr)),
        StatusIs(StatusCode::kInvalidArgument));
  }

  // Expressions evaluating to non-scalar values should also be rejected.
  for (std::string key : {"exact32", "ternary32", "lpm32", "range32"}) {
    EXPECT_THAT(ReasonEntryViolatesConstraint(kTableEntry,
                                              MakeConstraintInfo(KeyExpr(key))),
                StatusIs(StatusCode::kInvalidArgument));
  }
}

TEST_F(ReasonEntryViolatesConstraintTest, EntriesWithLeadingZeroesWork) {
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
  ASSERT_THAT(ReasonEntryViolatesConstraint(
                  kTableEntry, MakeConstraintInfo(exact_equals_num)),
              IsOkAndHolds(Eq("")));

  // Modify entry to have leading zeroes.
  p4::v1::TableEntry modified_entry = kTableEntry;
  modified_entry.mutable_match(0)->mutable_exact()->set_value(
      absl::StrCat(std::string{'\0'}, kTableEntry.match(0).exact().value()));
  EXPECT_THAT(ReasonEntryViolatesConstraint(
                  modified_entry, MakeConstraintInfo(exact_equals_num)),
              IsOkAndHolds(Eq("")));
}

TEST_F(ReasonEntryViolatesConstraintTest, EntriesWithOnlyZeroesWork) {
  Expression exact_equals_num = ParseTextProtoOrDie<Expression>(R"pb(
    start_location { table_name: "table" }
    end_location { table_name: "table" }
    type { boolean {} }
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
            integer_constant: "0"
          }
        }
      }
    }
  )pb");

  // Unmodified entry should not meet constraint since exact32 != 0.
  ASSERT_THAT(ReasonEntryViolatesConstraint(
                  kTableEntry, MakeConstraintInfo(exact_equals_num)),
              IsOkAndHolds(Not(Eq(""))));

  // Modify entry to be zero.
  p4::v1::TableEntry modified_entry = kTableEntry;
  modified_entry.mutable_match(0)->mutable_exact()->set_value(
      std::string{'\0'});
  ASSERT_THAT(ReasonEntryViolatesConstraint(
                  modified_entry, MakeConstraintInfo(exact_equals_num)),
              IsOkAndHolds(Eq("")));
}

TEST_F(ReasonEntryViolatesConstraintTest, EntriesWithZeroAsciiValueWorks) {
  Expression exact_equals_num = ParseTextProtoOrDie<Expression>(R"pb(
    start_location { table_name: "table" }
    end_location { table_name: "table" }
    type { boolean {} }
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
            integer_constant: "48"
          }
        }
      }
    }
  )pb");

  // Unmodified entry should not meet constraint since exact32 != 48.
  ASSERT_THAT(ReasonEntryViolatesConstraint(
                  kTableEntry, MakeConstraintInfo(exact_equals_num)),
              IsOkAndHolds(Not(Eq(""))));

  // Modify entry to be zero character.
  p4::v1::TableEntry modified_entry = kTableEntry;
  modified_entry.mutable_match(0)->mutable_exact()->set_value("0");
  ASSERT_THAT(ReasonEntryViolatesConstraint(
                  modified_entry, MakeConstraintInfo(exact_equals_num)),
              IsOkAndHolds(Eq("")));
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

TEST_F(ReasonEntryViolatesConstraintTest,
       PriorityConstraintWorksWithDefaultPriority) {
  const Expression kExpr = GetPriorityEqualityConstraint(0);
  const auto constraint_check_result =
      ReasonEntryViolatesConstraint(kTableEntry, MakeConstraintInfo(kExpr));
  ASSERT_THAT(constraint_check_result, IsOkAndHolds(Eq("")));
}

TEST_F(ReasonEntryViolatesConstraintTest,
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
    Expression expr = GetPriorityEqualityConstraint(0);
    expr.mutable_start_location()->set_table_name(kTableInfo.name);
    expr.mutable_end_location()->set_table_name(kTableInfo.name);

    const auto constraint_check_result = ReasonEntryViolatesConstraint(
        table_entry_with_priority, MakeConstraintInfo(expr));
    ASSERT_THAT(constraint_check_result, IsOkAndHolds(Not(Eq(""))));
  }

  // Equality to the same priority.
  {
    const Expression kExpr = GetPriorityEqualityConstraint(priority);
    const auto constraint_check_result = ReasonEntryViolatesConstraint(
        table_entry_with_priority, MakeConstraintInfo(kExpr));
    ASSERT_THAT(constraint_check_result, IsOkAndHolds(Eq("")));
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
                                  PrintTextProto(boolean(left)),
                                  PrintTextProto(boolean(right))));
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
  const std::vector<Integer> values = {
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
                                  PrintTextProto(int_const(left)),
                                  PrintTextProto(int_const(right))));
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
                                PrintTextProto(KeyExpr(key))));
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
    : public ReasonEntryViolatesConstraintTest {
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

TEST(ParseP4RTInteger, ParsesZeroCorrectly) {
  auto zero_string = std::string(1, '\0');
  ASSERT_EQ(zero_string.size(), 1);
  ASSERT_EQ(zero_string.at(0), '\0');
  EXPECT_THAT(ParseP4RTInteger(zero_string), Eq(0));
}

TEST(ParseP4RTInteger, ParsesTrailingZeroCorrectly) {
  std::string hex_string = {'\xe0', '\x00', '\x00', '\x00'};
  EXPECT_THAT(ParseP4RTInteger(hex_string), Eq(0xe0000000U));
}

}  // namespace
}  // namespace internal_interpreter
}  // namespace p4_constraints
