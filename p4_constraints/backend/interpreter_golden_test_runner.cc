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

// Generates file for golden testing of `ReasonEntryViolatesConstraint` in
// interpreter.cc. Expected output is `interpreter_golden_test_runner.expected`

#include <cstdint>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "gutil/ordered_map.h"
#include "gutil/testing.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/backend/interpreter.h"
#include "p4_constraints/backend/type_checker.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/frontend/constraint_kind.h"
#include "p4_constraints/frontend/parser.h"

namespace p4_constraints {
namespace internal_interpreter {

using ::gutil::ParseProtoOrDie;
using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::SourceLocation;
using ::p4_constraints::ast::Type;

// A test case for `ReasonEntryViolatesConstraint` function.
struct TestCase {
  std::string table_constraint;
  absl::btree_map<uint32_t, std::string> constraint_by_action_id;
  p4::v1::TableEntry table_entry;
  SourceLocation source_of_constraint_violated;
};

absl::StatusOr<ConstraintInfo> MakeConstraintInfo(TestCase test_case) {
  const Type kExact32 = ParseProtoOrDie<Type>("exact { bitwidth: 32 }");
  const Type kTernary32 = ParseProtoOrDie<Type>("ternary { bitwidth: 32 }");
  const Type kLpm32 = ParseProtoOrDie<Type>("lpm { bitwidth: 32 }");
  const Type kRange32 = ParseProtoOrDie<Type>("range { bitwidth: 32 }");
  const Type kOptional32 =
      ParseProtoOrDie<Type>("optional_match { bitwidth: 32 }");
  const Type kFixedUnsigned32 =
      ParseProtoOrDie<Type>("fixed_unsigned { bitwidth: 32 }");

  const TableInfo kTableInfo = {
      .id = 1,
      .name = "golden_table",
      .keys_by_id{
          {1, {1, "exact32", kExact32}}, {2, {2, "ternary32", kTernary32}}
          // For testing purposes, fine to omit the other keys here.
      },
      .keys_by_name{{"exact32", {1, "exact32", kExact32}},
                    {"ternary32", {2, "ternary32", kTernary32}},
                    {"lpm32", {3, "lpm32", kLpm32}},
                    {"range32", {4, "range32", kRange32}},
                    {"optional32", {5, "optional32", kOptional32}}}};

  const ActionInfo kMulticastGroupIdActionInfo = {
      .id = 1,
      .name = "multicast_group_id",
      .params_by_id{
          {1, {1, "multicast_group_id", kFixedUnsigned32}},
          {2, {2, "dummy_var", kFixedUnsigned32}},
      },
      .params_by_name{
          {"multicast_group_id", {1, "multicast_group_id", kFixedUnsigned32}},
          {"dummy_var", {2, "dummy_var", kFixedUnsigned32}},
      }};

  const ActionInfo kVlanIdActionInfo = {
      .id = 2,
      .name = "vlan_id",
      .params_by_id{{1, {1, "vlan_id", kFixedUnsigned32}}},
      .params_by_name{{"vlan_id", {1, "vlan_id", kFixedUnsigned32}}}};

  const absl::flat_hash_map<uint32_t, ActionInfo> kActionInfoById = {
      {kMulticastGroupIdActionInfo.id, kMulticastGroupIdActionInfo},
      {kVlanIdActionInfo.id, kVlanIdActionInfo},
  };

  TableInfo table_info = kTableInfo;

  if (!test_case.table_constraint.empty()) {
    table_info.constraint_source = {
        .constraint_string = test_case.table_constraint,
        .constraint_location = test_case.source_of_constraint_violated,
    };
    ASSIGN_OR_RETURN(Expression constraint,
                     ParseConstraint(ConstraintKind::kTableConstraint,
                                     table_info.constraint_source));
    RETURN_IF_ERROR(InferAndCheckTypes(&constraint, table_info));
    table_info.constraint = constraint;
  }
  absl::flat_hash_map<uint32_t, ActionInfo> action_info_by_id;
  if (!test_case.constraint_by_action_id.empty()) {
    for (const auto& [action_id, constraint_string] :
         test_case.constraint_by_action_id) {
      ActionInfo action_info = kActionInfoById.at(action_id);
      action_info.constraint_source = {
          .constraint_string = constraint_string,
          .constraint_location = test_case.source_of_constraint_violated,
      };
      ASSIGN_OR_RETURN(Expression constraint,
                       ParseConstraint(ConstraintKind::kActionConstraint,
                                       action_info.constraint_source));
      RETURN_IF_ERROR(InferAndCheckTypes(&constraint, action_info));
      action_info.constraint = constraint;
      action_info_by_id.insert({action_id, action_info});
    }
  }

  return ConstraintInfo{
      .action_info_by_id = action_info_by_id,
      .table_info_by_id{
          {table_info.id, table_info},
      },
  };
}

// NOTE: Test cases only define the "exact" field for brevity but kTableInfo
// is composed of several keys. These undeclared keys are implicitly set to
// hold "catchall" values (i.e. range=[min,max], ternary=*).
std::vector<TestCase> TestCases() {
  std::vector<TestCase> test_cases;
  ast::SourceLocation file_path;
  ast::SourceLocation table_name;
  ast::SourceLocation action_name;

  *file_path.mutable_file_path() = "golden_test.p4";
  *table_name.mutable_table_name() = "golden_table";
  *action_name.mutable_action_name() = "golden_action";

  test_cases.push_back(TestCase{
      .table_constraint = "true;",
      .constraint_by_action_id{{1, "multicast_group_id != 0"}},
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
        action {
          action {
            action_id: 1
            params { param_id: 1 value: "\x0" }
          }
        }
      )pb"),
      .source_of_constraint_violated = file_path,
  });

  test_cases.push_back(TestCase{
      .constraint_by_action_id{{1, "multicast_group_id != 0"}},
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        action {
          action {
            action_id: 1
            params { param_id: 1 value: "\x0" }
          }
        }
      )pb"),
      .source_of_constraint_violated = action_name,
  });

  test_cases.push_back(TestCase{
      .constraint_by_action_id{{1, "multicast_group_id != 0"}},
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        action {
          action {
            action_id: 1
            params { param_id: 1 value: "\x6" }
          }
        }
      )pb"),
      .source_of_constraint_violated = action_name,
  });

  test_cases.push_back(TestCase{
      .constraint_by_action_id{{1, "multicast_group_id != dummy_var"}},
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        action {
          action {
            action_id: 1
            params { param_id: 1 value: "\x6" },
            params { param_id: 2 value: "\x0" }
          }
        }
      )pb"),
      .source_of_constraint_violated = action_name,
  });

  test_cases.push_back(TestCase{
      .constraint_by_action_id{{1, "multicast_group_id != 0"},
                               {2, "vlan_id != 0"}},
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        action {
          action_profile_action_set {
            action_profile_actions {
              action {
                action_id: 1
                params { param_id: 1 value: "\x6" }
              }
              weight: 1
            }
            action_profile_actions {
              action {
                action_id: 2
                params { param_id: 1 value: "\x6" }
              }
              weight: 2
            }
          }
        }
      )pb"),
      .source_of_constraint_violated = action_name,
  });

  test_cases.push_back(TestCase{
      .constraint_by_action_id{{1, "multicast_group_id != 0"},
                               {2, "vlan_id != 0"}},
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        action {
          action_profile_action_set {
            action_profile_actions {
              action {
                action_id: 1
                params { param_id: 1 value: "\x6" }
              }
              weight: 1
            }
            action_profile_actions {
              action {
                action_id: 2
                params { param_id: 1 value: "\x0" }
              }
              weight: 2
            }
          }
        }
      )pb"),
      .source_of_constraint_violated = action_name,
  });

  test_cases.push_back(TestCase{
      .table_constraint = "true;",
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_of_constraint_violated = table_name,
  });

  test_cases.push_back(TestCase{
      .table_constraint = "exact32::value != 10 || exact32::value == 10;",
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_of_constraint_violated = table_name,
  });

  test_cases.push_back(TestCase{
      .table_constraint = "exact32::value > 6 && exact32::value < 5;",
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
        match {
          field_id: 2
          ternary { value: "\012" mask: "\100" }
        }
      )pb"),
      .source_of_constraint_violated = table_name,
  });

  test_cases.push_back(TestCase{
      .table_constraint = "exact32::value > 5;\n"
                          "exact32::value < 20;\n"
                          "exact32::value == 14;",
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_of_constraint_violated = table_name,
  });

  test_cases.push_back(TestCase{
      .table_constraint = "exact32::value > 0;\n"
                          "exact32::value > 7 || exact32::value == 5;\n"
                          "exact32::value == 9;",
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_of_constraint_violated = file_path,
  });

  test_cases.push_back(TestCase{
      .table_constraint = "exact32::value > 0;\n"
                          "exact32::value < 42;\n"
                          "exact32::value < 20 -> exact32::value == 14;",
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_of_constraint_violated = file_path,
  });

  test_cases.push_back(TestCase{
      .table_constraint = "exact32::value == 1 || exact32::value == 2;\n"
                          "!(exact32::value == 10 -> exact32::value == 10);\n"
                          "exact32::value == 3 || exact32::value == 4;",
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_of_constraint_violated = file_path,
  });

  test_cases.push_back(TestCase{
      .table_constraint = "exact32::value == 80 || ternary32::value == 3096;\n"
                          "ternary32::mask == 255 && exact32::value == 3;",
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
        match {
          field_id: 2
          ternary { value: "\052" mask: "\100" }
        }
      )pb"),
      .source_of_constraint_violated = table_name,
  });

  test_cases.push_back(TestCase{
      .table_constraint =
          "(false || false) && (!(true -> true) && (false || false));",
      .table_entry = ParseProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_of_constraint_violated = file_path,
  });

  return test_cases;
}

absl::StatusOr<std::string> EntryToString(const EvaluationContext& context,
                                          const TableInfo& table_info) {
  const TableEntry* table_entry =
      std::get_if<TableEntry>(&context.constraint_context);

  if (table_entry == nullptr) {
    return gutil::InvalidArgumentErrorBuilder()
           << "The constraint context does not contain a TableEntry.";
  }
  std::string key_info = absl::StrJoin(
      gutil::AsOrderedView(table_entry->keys), "\n",
      [](std::string* out, auto pair) {
        absl::StrAppend(out, "Key:\"", pair.first,
                        "\" -> Value: ", EvalResultToString(pair.second));
      });

  return absl::StrFormat(
      "Table Name: \"%s\"\n"
      "Priority:%d\n"
      "%s\n",
      table_entry->table_name, table_entry->priority, key_info);
}

absl::StatusOr<std::string> ActionToString(const EvaluationContext& context) {
  const ActionInvocation* action_invocation =
      std::get_if<ActionInvocation>(&context.constraint_context);
  if (action_invocation == nullptr) {
    return gutil::InvalidArgumentErrorBuilder()
           << "The constraint context does not contain an "
              "ActionInvocation.";
  }
  std::string param_info = absl::StrJoin(
      gutil::AsOrderedView(action_invocation->action_parameters), "\n",
      [](std::string* out, auto pair) {
        absl::StrAppend(out, "-- Action Parameter:\"", pair.first,
                        "\" -> Value: ", EvalResultToString(pair.second));
      });

  return absl::StrFormat(
      "Action Name: \"%s\"\n"
      "%s\n",
      action_invocation->action_name, param_info);
}

absl::StatusOr<std::string> ActionToString(
    const p4::v1::Action& action, const ConstraintInfo& constraint_info) {
  const uint32_t action_id = action.action_id();
  auto* action_info = GetActionInfoOrNull(constraint_info, action_id);
  if (action_info == nullptr) {
    return absl::InvalidArgumentError("No action info");
  }
  ASSIGN_OR_RETURN(const EvaluationContext context,
                   ParseAction(action, *action_info));

  return ActionToString(context);
}

absl::StatusOr<std::string> ActionToString(
    const p4::v1::ActionProfileActionSet& action_set,
    const ConstraintInfo& constraint_info) {
  std::string action_set_string;
  for (const p4::v1::ActionProfileAction& action_profile_action :
       action_set.action_profile_actions()) {
    ASSIGN_OR_RETURN(
        std::string action_string,
        ActionToString(action_profile_action.action(), constraint_info));
    absl::StrAppend(&action_set_string, action_string);
  }
  return action_set_string;
}

absl::Status main() {
  for (const TestCase& test_case : TestCases()) {
    std::cout << "### ReasonEntryViolatestConstraint Test ###################\n"
              << "=== INPUT ===\n";

    if (!test_case.table_constraint.empty()) {
      std::cout << "--- Table Constraint ---\n"
                << test_case.table_constraint << "\n";
    }
    std::cout << "--- Table Entry Info ---\n";
    ASSIGN_OR_RETURN(ConstraintInfo constraint_info,
                     MakeConstraintInfo(test_case));
    if (!test_case.table_constraint.empty()) {
      auto* table_info = GetTableInfoOrNull(constraint_info, 1);
      if (table_info == nullptr) {
        return absl::InvalidArgumentError("No table info");
      }
      ASSIGN_OR_RETURN(const EvaluationContext context,
                       ParseTableEntry(test_case.table_entry, *table_info));
      absl::StatusOr<std::string> entry = EntryToString(context, *table_info);
      if (!entry.ok()) {
        std::cout << "=== ERROR ===\n" << entry.status();
        return absl::InvalidArgumentError(entry.status().ToString());
      }
      std::cout << *entry << "\n";
    }

    if (!test_case.constraint_by_action_id.empty()) {
      switch (test_case.table_entry.action().type_case()) {
        case p4::v1::TableAction::kAction: {
          ASSIGN_OR_RETURN(
              std::string action_string,
              ActionToString(test_case.table_entry.action().action(),
                             constraint_info));
          std::cout << action_string << "\n";
          break;
        }
        case p4::v1::TableAction::kActionProfileMemberId:
        case p4::v1::TableAction::kActionProfileGroupId:
          return gutil::InvalidArgumentErrorBuilder()
                 << "action restrictions not supported for entries with the "
                    "given kind of action: "
                 << test_case.table_entry.DebugString();
        case p4::v1::TableAction::kActionProfileActionSet: {
          ASSIGN_OR_RETURN(
              std::string action_string,
              ActionToString(
                  test_case.table_entry.action().action_profile_action_set(),
                  constraint_info));
          std::cout << action_string << "\n";
          break;
        }
        case p4::v1::TableAction::TYPE_NOT_SET:
          return gutil::InvalidArgumentErrorBuilder()
                 << "unknown action type "
                 << test_case.table_entry.DebugString();
      }
    }

    // Print action constraint(s).
    if (!test_case.constraint_by_action_id.empty()) {
      for (const auto& [action_id, constraint] :
           test_case.constraint_by_action_id) {
        auto* action_info = GetActionInfoOrNull(constraint_info, action_id);
        if (action_info == nullptr) {
          return absl::InvalidArgumentError("No action info");
        }
        std::cout << "--- Action Constraint for Action: " << action_info->name
                  << " ---\n";
        std::cout << constraint << "\n";
      }
    }

    // Print an explanation for why an entry violates a table/action constraint.
    absl::StatusOr<std::string> result =
        ReasonEntryViolatesConstraint(test_case.table_entry, constraint_info);
    if (result.ok()) {
      std::cout << "=== OUTPUT ===\n"
                << (result->empty() ? "<empty>\n" : *result) << "\n";
    } else {
      std::cout << "=== ERROR ===\n" << result.status();
      return absl::InvalidArgumentError(result.status().ToString());
    }
  }
  return absl::OkStatus();
}

}  // namespace internal_interpreter
}  // namespace p4_constraints

int main() { CHECK_OK(p4_constraints::internal_interpreter::main()); }
