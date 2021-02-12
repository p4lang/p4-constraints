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

#include "p4_constraints/backend/constraint_info.h"

#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "absl/types/variant.h"
#include "gutils/ret_check.h"
#include "gutils/status_macros.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/type_checker.h"
#include "p4_constraints/frontend/lexer.h"
#include "p4_constraints/frontend/parser.h"
#include "re2/re2.h"
#include "re2/stringpiece.h"

namespace p4_constraints {

namespace {

using p4::config::v1::MatchField;
using p4::config::v1::Table;

absl::StatusOr<absl::optional<ast::Expression>> ParseTableConstraint(
    const Table& table) {
  // We expect .p4 files to have the following format:
  // ```p4
  //   @file(__FILE__)              // optional
  //   @line(__LINE__)              // optional
  //   @entry_restriction("
  //      <the actual constraint>
  //   ")
  //   table foo { ... }
  // ```
  // The @file/@line annotations are optional and intended for debugging/testing
  // only; they allows us to give error messages that quote the source code.
  const RE2 file_annotation = {R"RE(@file[(]"([^"]*)"[)])RE"};
  const RE2 line_annotation = {R"RE(@line[(](\d+)[)])RE"};
  const RE2 constraint_annotation = {R"RE(@entry_restriction)RE"};

  ast::SourceLocation location;
  int line = 0;
  absl::string_view constraint = "";
  for (re2::StringPiece annotation : table.preamble().annotations()) {
    if (RE2::Consume(&annotation, file_annotation,
                     location.mutable_file_path()))
      continue;
    if (RE2::Consume(&annotation, line_annotation, &line)) continue;
    if (RE2::Consume(&annotation, constraint_annotation)) {
      constraint = annotation.data();
      break;
    }
  }
  location.set_line(line);
  if (location.file_path().empty()) {
    location.set_table_name(table.preamble().name());
  }

  if (constraint.empty()) {
    return absl::optional<ast::Expression>();
  }
  if (!absl::ConsumePrefix(&constraint, "(\"") ||
      !absl::ConsumeSuffix(&constraint, "\")")) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "In table " << table.preamble().name() << ":\n"
           << "Syntax error: @entry_restriction must be enclosed in "
              "'(\"' and '\")'";
  }
  // TODO(smolkaj): With C++17, we can use std::string_view throughout and
  // won't need to make an extra copy here.
  const auto constraint_str = std::string(constraint);
  return ParseConstraint(Tokenize(constraint_str, location));
}

absl::StatusOr<ast::Type> ParseKeyType(const MatchField& key) {
  ast::Type type;
  switch (key.match_case()) {
    case MatchField::kMatchType:
      switch (key.match_type()) {
        case MatchField::EXACT:
          type.mutable_exact()->set_bitwidth(key.bitwidth());
          return type;
        case MatchField::TERNARY:
          type.mutable_ternary()->set_bitwidth(key.bitwidth());
          return type;
        case MatchField::LPM:
          type.mutable_lpm()->set_bitwidth(key.bitwidth());
          return type;
        case MatchField::RANGE:
          type.mutable_range()->set_bitwidth(key.bitwidth());
          return type;
        default:
          return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
                 << "match key of invalid MatchType: "
                 << MatchField::MatchType_Name(key.match_type());
      }
    case MatchField::kOtherMatchType:
      *type.mutable_unsupported()->mutable_name() = key.other_match_type();
      return type;
    default:
      return gutils::InternalErrorBuilder(GUTILS_LOC)
             << "unknown MatchField.match case: " << key.match_case();
  }
}

absl::StatusOr<TableInfo> ParseTableInfo(const Table& table) {
  absl::flat_hash_map<uint32_t, KeyInfo> keys_by_id;
  absl::flat_hash_map<std::string, KeyInfo> keys_by_name;

  for (const MatchField& key : table.match_fields()) {
    ASSIGN_OR_RETURN(const ast::Type type, ParseKeyType(key));
    const KeyInfo key_info{.id = key.id(), .name = key.name(), .type = type};
    if (!keys_by_id.insert({key_info.id, key_info}).second) {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "table " << table.preamble().name()
             << " has duplicate key: " << key.DebugString();
    }
    if (!keys_by_name.insert({key_info.name, key_info}).second) {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "table " << table.preamble().name()
             << " has duplicate key: " << key.DebugString();
    }
  }

  TableInfo table_info{.id = table.preamble().id(),
                       .name = table.preamble().name(),
                       .constraint = {},  // Inserted in a second.
                       .keys_by_id = keys_by_id,
                       .keys_by_name = keys_by_name};

  // Parse and type check constraint.
  ASSIGN_OR_RETURN(table_info.constraint, ParseTableConstraint(table));
  if (table_info.constraint.has_value()) {
    RETURN_IF_ERROR(
        InferAndCheckTypes(&table_info.constraint.value(), table_info));
  }

  return table_info;
}

}  // namespace

absl::StatusOr<ConstraintInfo> P4ToConstraintInfo(
    const p4::config::v1::P4Info& p4info) {
  // Allocate output.
  absl::flat_hash_map<uint32_t, TableInfo> info;
  std::vector<absl::Status> errors;

  for (const Table& table : p4info.tables()) {
    absl::StatusOr<TableInfo> table_info = ParseTableInfo(table);
    if (!table_info.ok()) {
      errors.push_back(table_info.status());
    } else if (!info.insert({table.preamble().id(), table_info.value()})
                    .second) {
      errors.push_back(gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
                       << "duplicate table: " << table.DebugString());
    }
  }
  if (errors.empty()) return info;
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << "P4Info to constraint info translation failed with the following "
            "errors:\n\n-"
         << absl::StrJoin(errors, "\n\n- ",
                          [](std::string* out, const absl::Status& status) {
                            absl::StrAppend(out, status.ToString());
                          });
}

}  // namespace p4_constraints
