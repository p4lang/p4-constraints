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

// Generates file for golden testing of `ReasonEntryViolatesConstraint` in
// interpreter.cc. Expected output is `interpreter_golden_test_runner.expected`

#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_join.h"
#include "gutils/ordered_map.h"
#include "gutils/parse_text_proto.h"
#include "gutils/status_macros.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/backend/interpreter.h"
#include "p4_constraints/backend/type_checker.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/frontend/parser.h"

namespace p4_constraints {
namespace internal_interpreter {

using ::gutils::ParseTextProtoOrDie;
using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::SourceLocation;
using ::p4_constraints::ast::Type;

// A test case for `ReasonEntryViolatesConstraint` function.
struct TestCase {
  std::string constraint;
  p4::v1::TableEntry table_entry;
  bool source_file_available;
};

absl::StatusOr<ConstraintInfo> MakeConstraintInfo(TestCase test_case) {
  const Type kExact32 = ParseTextProtoOrDie<Type>("exact { bitwidth: 32 }");
  const Type kTernary32 = ParseTextProtoOrDie<Type>("ternary { bitwidth: 32 }");
  const Type kLpm32 = ParseTextProtoOrDie<Type>("lpm { bitwidth: 32 }");
  const Type kRange32 = ParseTextProtoOrDie<Type>("range { bitwidth: 32 }");
  const Type kOptional32 =
      ParseTextProtoOrDie<Type>("optional_match { bitwidth: 32 }");
  const TableInfo kTableInfo{
      .id = 1,
      .name = "golden_table",
      .keys_by_id =
          {
              {1, {1, "exact32", kExact32}}, {2, {2, "ternary32", kTernary32}},
              // For testing purposes, fine to omit the other keys here.
          },
      .keys_by_name = {
          {"exact32", {1, "exact32", kExact32}},
          {"ternary32", {2, "ternary32", kTernary32}},
          {"lpm32", {3, "lpm32", kLpm32}},
          {"range32", {4, "range32", kRange32}},
          {"optional32", {5, "optional32", kOptional32}},
      }};

  ConstraintSource source{
      .constraint_string = test_case.constraint,
      .constraint_location = SourceLocation(),
  };
  if (test_case.source_file_available) {
    *source.constraint_location.mutable_file_path() = "golden_test.p4";
  } else {
    *source.constraint_location.mutable_table_name() = kTableInfo.name;
  }

  TableInfo table_info = kTableInfo;
  table_info.constraint_source = source;
  ASSIGN_OR_RETURN(Expression expression, ParseConstraint(source));
  CHECK_OK(InferAndCheckTypes(&(expression), kTableInfo));
  table_info.constraint = expression;
  return ConstraintInfo{{table_info.id, table_info}};
}

// NOTE: Test cases only define the "exact" field for brevity but kTableInfo is
// composed of several keys. These undeclared keys are implicitly set to hold
// "catchall" values (i.e. range=[min,max], ternary=*).
std::vector<TestCase> TestCases() {
  std::vector<TestCase> test_cases;
  test_cases.push_back(TestCase{
      .constraint = "true;",
      .table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_file_available = false,
  });

  test_cases.push_back(TestCase{
      .constraint = "exact32::value != 10 || exact32::value == 10;",
      .table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_file_available = false,
  });

  test_cases.push_back(TestCase{
      .constraint = "exact32::value > 6 && exact32::value < 5;",
      .table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_file_available = false,
  });

  test_cases.push_back(TestCase{
      .constraint = "exact32::value > 5;\n"
                    "exact32::value < 20;\n"
                    "exact32::value == 14;",
      .table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_file_available = false,
  });

  test_cases.push_back(TestCase{
      .constraint = "exact32::value > 0;\n"
                    "exact32::value > 7 || exact32::value == 5;\n"
                    "exact32::value == 9;",
      .table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_file_available = true,
  });

  test_cases.push_back(TestCase{
      .constraint = "exact32::value > 0;\n"
                    "exact32::value < 42;\n"
                    "exact32::value < 20 -> exact32::value == 14;",
      .table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_file_available = true,
  });

  test_cases.push_back(TestCase{
      .constraint = "exact32::value == 1 || exact32::value == 2;\n"
                    "!(exact32::value == 10 -> exact32::value == 10);\n"
                    "exact32::value == 3 || exact32::value == 4;",
      .table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_file_available = true,
  });

  test_cases.push_back(TestCase{
      .constraint = "exact32::value == 80 || ternary32::value == 3096;\n"
                    "ternary32::mask == 255 && exact32::value == 3;",
      .table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
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
      .source_file_available = false,
  });

  test_cases.push_back(TestCase{
      .constraint =
          "(false || false) && (!(true -> true) && (false || false));",
      .table_entry = ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
        table_id: 1
        match {
          field_id: 1
          exact { value: "\012" }
        }
      )pb"),
      .source_file_available = true,
  });

  return test_cases;
}

std::string EntryToString(const TableEntry& entry) {
  std::string key_info = absl::StrJoin(
      gutils::Ordered(entry.keys), "\n", [](std::string* out, auto pair) {
        absl::StrAppend(out, "Key:\"", pair.first,
                        "\" -> Value: ", EvalResultToString(pair.second));
      });
  return absl::StrFormat(
      "Table Name: \"%s\"\n"
      "Priority:%d\n"
      "%s\n",
      entry.table_name, entry.priority, key_info);
}

absl::Status main() {
  for (const TestCase& test_case : TestCases()) {
    ASSIGN_OR_RETURN(ConstraintInfo constraint_info,
                     MakeConstraintInfo(test_case));
    ASSIGN_OR_RETURN(TableEntry input,
                     ParseEntry(test_case.table_entry, constraint_info.at(1)));
    std::cout << "### ReasonEntryViolatestConstraint Test ###################\n"
              << "=== INPUT ===\n"
              << "--- Constraint ---\n"
              << test_case.constraint << "\n"
              << "--- Table Entry ---\n"
              << EntryToString(input) << "\n";

    absl::StatusOr<std::string> result =
        ReasonEntryViolatesConstraint(test_case.table_entry, constraint_info);
    if (result.ok()) {
      std::cout << "=== OUTPUT ===\n"
                << (result->empty() ? "<empty>\n" : *result) << "\n";
    } else {
      std::cout << "=== ERROR ===\n" << result.status();
    }
  }
  return absl::OkStatus();
}

}  // namespace internal_interpreter
}  // namespace p4_constraints

int main() { CHECK_OK(p4_constraints::internal_interpreter::main()); }
