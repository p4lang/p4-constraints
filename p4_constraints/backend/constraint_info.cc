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

#include <stdint.h>

#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "absl/types/optional.h"
#include "gutils/status_macros.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4/config/v1/p4types.pb.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/type_checker.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/frontend/constraint_kind.h"
#include "p4_constraints/frontend/parser.h"
#include "re2/re2.h"

namespace p4_constraints {

namespace {

using p4::config::v1::Action;
using p4::config::v1::Action_Param;
using p4::config::v1::MatchField;
using p4::config::v1::Preamble;
using p4::config::v1::Table;
using p4_constraints::ConstraintKind;

RE2 GetConstraintAnnotation(ConstraintKind constraint_kind) {
  switch (constraint_kind) {
    case ConstraintKind::kTableConstraint:
      return {R"RE(@entry_restriction)RE"};
    case ConstraintKind::kActionConstraint:
      return {R"RE(@action_restriction)RE"};
  }
  LOG(ERROR)
      << "ConstraintKind is neither TableConstraint nor ActionConstraint";
  return RE2("");
}

void SetConstraintLocationName(ConstraintKind constraint_kind,
                               absl::string_view name,
                               ast::SourceLocation& source_location) {
  switch (constraint_kind) {
    case ConstraintKind::kTableConstraint:
      source_location.set_table_name(name);
      return;
    case ConstraintKind::kActionConstraint:
      source_location.set_action_name(name);
      return;
  }
  LOG(ERROR)
      << "ConstraintKind is neither TableConstraint nor ActionConstraint";
}

absl::StatusOr<absl::optional<ConstraintSource>> ExtractConstraint(
    ConstraintKind constraint_kind, const Preamble& preamble) {
  // We expect .p4 files to have the following format for tables:
  // ```p4
  //   @file(__FILE__)              // optional
  //   @line(__LINE__)              // optional
  //   @entry_restriction("
  //      <the actual constraint>
  //   ")
  //   table foo { ... }
  // ```
  // We expect .p4 files to have the following format for actions:
  // ```p4
  //   @file(__FILE__)              // optional
  //   @line(__LINE__)              // optional
  //   @action_restriction("
  //      <the actual constraint>
  //   ")
  //   action bar { ... }
  // ```
  // The @file/@line annotations are optional and intended for
  // debugging/testing only; they allows us to give error messages that quote
  // the source code.
  const RE2 file_annotation = {R"RE(@file[(]"([^"]*)"[)])RE"};
  const RE2 line_annotation = {R"RE(@line[(](\d+)[)])RE"};
  const RE2 constraint_annotation = GetConstraintAnnotation(constraint_kind);

  absl::string_view constraint_string = "";
  ast::SourceLocation constraint_location;
  int line = 0;
  for (absl::string_view annotation : preamble.annotations()) {
    if (RE2::Consume(&annotation, file_annotation,
                     constraint_location.mutable_file_path()))
      continue;
    if (RE2::Consume(&annotation, line_annotation, &line)) continue;
    if (RE2::Consume(&annotation, constraint_annotation)) {
      constraint_string = annotation.data();
      break;
    }
  }

  if (constraint_string.empty()) return absl::nullopt;

  constraint_location.set_line(line);
  if (constraint_location.file_path().empty()) {
    SetConstraintLocationName(constraint_kind, preamble.name(),
                              constraint_location);
  }

  if (!absl::ConsumePrefix(&constraint_string, "(\"") ||
      !absl::ConsumeSuffix(&constraint_string, "\")")) {
    bool is_table = constraint_kind == ConstraintKind::kTableConstraint;
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "In " << (is_table ? "table " : "action ") << preamble.name()
           << ":\n"
           << "Syntax error: @" << (is_table ? "entry" : "action")
           << "_restriction must be enclosed in '(\"' and '\")'";
  }
  return ConstraintSource{
      .constraint_string = std::string(constraint_string),
      .constraint_location = constraint_location,
  };
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
        case MatchField::OPTIONAL:
          type.mutable_optional_match()->set_bitwidth(key.bitwidth());
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

absl::StatusOr<ast::Type> ParseParamType(const Action_Param& param) {
  ast::Type type;
  // P4NamedType is unset if the param does not use a user-defined type.
  // Currently we do not support user-defined types.
  if (!param.type_name().name().empty()) {
    type.mutable_unsupported()->set_name(param.type_name().name());
    return type;
  }

  type.mutable_fixed_unsigned()->set_bitwidth(param.bitwidth());
  return type;
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
             << " has duplicate key: " << absl::StrCat(key);
    }
    if (!keys_by_name.insert({key_info.name, key_info}).second) {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "table " << table.preamble().name()
             << " has duplicate key: " << absl::StrCat(key);
    }
  }

  ASSIGN_OR_RETURN(
      absl::optional<ConstraintSource> constraint_source,
      ExtractConstraint(ConstraintKind::kTableConstraint, table.preamble()));

  absl::optional<ast::Expression> constraint = absl::nullopt;
  if (constraint_source.has_value()) {
    ASSIGN_OR_RETURN(
        constraint,
        ParseConstraint(ConstraintKind::kTableConstraint, *constraint_source));
  }

  TableInfo table_info{
      .id = table.preamble().id(),
      .name = table.preamble().name(),
      .constraint = constraint,
      .constraint_source = constraint_source.value_or(ConstraintSource()),
      .keys_by_id = keys_by_id,
      .keys_by_name = keys_by_name,
  };

  // Type check constraint.
  if (table_info.constraint.has_value()) {
    RETURN_IF_ERROR(InferAndCheckTypes(&*table_info.constraint, table_info));
  }

  return table_info;
}

absl::StatusOr<ActionInfo> ParseActionInfo(const Action& action) {
  absl::flat_hash_map<uint32_t, ParamInfo> params_by_id;
  absl::flat_hash_map<std::string, ParamInfo> params_by_name;

  for (const Action_Param& param : action.params()) {
    ASSIGN_OR_RETURN(const ast::Type type, ParseParamType(param));
    const ParamInfo param_info{
        .id = param.id(),
        .name = param.name(),
        .type = type,
    };
    if (!params_by_id.insert({param_info.id, param_info}).second) {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "action " << action.preamble().name()
             << " has duplicate param: " << absl::StrCat(param);
    }
    if (!params_by_name.insert({param_info.name, param_info}).second) {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "action " << action.preamble().name()
             << " has duplicate param: " << absl::StrCat(param);
    }
  }
  ASSIGN_OR_RETURN(
      absl::optional<ConstraintSource> constraint_source,
      ExtractConstraint(ConstraintKind::kActionConstraint, action.preamble()));
  absl::optional<ast::Expression> constraint;
  if (constraint_source.has_value()) {
    ASSIGN_OR_RETURN(
        constraint,
        ParseConstraint(ConstraintKind::kActionConstraint, *constraint_source));
  }
  ActionInfo action_info{
      .id = action.preamble().id(),
      .name = action.preamble().name(),
      .constraint = constraint,
      .constraint_source = constraint_source.value_or(ConstraintSource()),
      .params_by_id = params_by_id,
      .params_by_name = params_by_name,
  };
  // Type check constraint.
  if (action_info.constraint.has_value()) {
    RETURN_IF_ERROR(InferAndCheckTypes(&*action_info.constraint, action_info));
  }
  return action_info;
}

}  // namespace

std::optional<AttributeInfo> GetAttributeInfo(
    absl::string_view attribute_name) {
  // ArbitraryInt ast type.
  ast::Type arbitrary_int;
  arbitrary_int.mutable_arbitrary_int();

  if (attribute_name == "priority") {
    return AttributeInfo{.name = "priority", .type = arbitrary_int};
  }

  // Unknown attribute.
  return absl::nullopt;
}

const TableInfo* GetTableInfoOrNull(const ConstraintInfo& constraint_info,
                                    uint32_t table_id) {
  auto it = constraint_info.table_info_by_id.find(table_id);
  if (it == constraint_info.table_info_by_id.end()) return nullptr;
  return &it->second;
}

const ActionInfo* GetActionInfoOrNull(const ConstraintInfo& constraint_info,
                                      uint32_t action_id) {
  auto it = constraint_info.action_info_by_id.find(action_id);
  if (it == constraint_info.action_info_by_id.end()) return nullptr;
  return &it->second;
}

absl::StatusOr<ConstraintInfo> P4ToConstraintInfo(
    const p4::config::v1::P4Info& p4info) {
  // Allocate output.
  absl::flat_hash_map<uint32_t, ActionInfo> action_info_by_id;
  absl::flat_hash_map<uint32_t, TableInfo> table_info_by_id;

  std::vector<absl::Status> errors;

  for (const Table& table : p4info.tables()) {
    absl::StatusOr<TableInfo> table_info = ParseTableInfo(table);
    if (!table_info.ok()) {
      errors.push_back(table_info.status());
    } else if (!table_info_by_id.insert({table.preamble().id(), *table_info})
                    .second) {
      errors.push_back(gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
                       << "duplicate table: " << absl::StrCat(table));
    }
  }

  for (const Action& action : p4info.actions()) {
    absl::StatusOr<ActionInfo> action_info = ParseActionInfo(action);
    if (!action_info.ok()) {
      errors.push_back(action_info.status());
    } else if (!action_info_by_id.insert({action.preamble().id(), *action_info})
                    .second) {
      errors.push_back(gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
                       << "duplicate action: " << absl::StrCat(action));
    }
  }

  if (errors.empty()) {
    ConstraintInfo info{
        .action_info_by_id = std::move(action_info_by_id),
        .table_info_by_id = std::move(table_info_by_id),
    };
    return info;
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << "P4Info to constraint info translation failed with the following "
            "errors:\n- "
         << absl::StrJoin(errors, "\n- ",
                          [](std::string* out, const absl::Status& status) {
                            absl::StrAppend(out, status.message(), "\n");
                          });
}

}  // namespace p4_constraints
