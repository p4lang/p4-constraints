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

#include "p4_constraints/quote.h"

#include <sstream>
#include <string>

#include "absl/log/log.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "gutils/proto.h"
#include "gutils/source_location.h"
#include "gutils/status_builder.h"
#include "gutils/status_macros.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"

namespace p4_constraints {

namespace {

// Returns a string explaining the source location interval, e.g.:
//    - succinct (when file is given): "path/to/file:12:20-25:"
//    - verbose (when table name is given):
//        "In constraint of table foo:\nAt offset line 12, columns 20 to 25:"
absl::StatusOr<std::string> Explain(const ast::SourceLocation& start,
                                    const ast::SourceLocation& end) {
  std::stringstream output;
  switch (start.source_case()) {
    case ast::SourceLocation::kFilePath:
      // Succinct mode: path/to/file:line:column.
      output << start.file_path() << ":" << (start.line() + 1) << ":"
             << (start.column() + 1);
      if (end.line() > start.line())
        output << "-" << (end.line() + 1) << ":" << end.column();
      else if (end.column() > start.column() + 1)
        output << "-" << end.column();
      output << ":\n";
      return output.str();

    case ast::SourceLocation::kActionName:
      output << "In @action_restriction of action '" << start.action_name()
             << "'; at offset line " << (start.line() + 1);
      if (end.line() > start.line())
        output << ", column " << (start.column() + 1) << " to line "
               << (end.line() + 1) << ", column" << end.column();
      else if (end.column() > start.column() + 1)
        output << ", columns " << (start.column() + 1) << " to "
               << end.column();
      else
        output << ", column " << (start.column() + 1);
      output << ":\n";
      return output.str();

    case ast::SourceLocation::kTableName:
      // Verbose mode: At offset line 12, columns 17 to 20.
      output << "In @entry_restriction of table '" << start.table_name()
             << "'; at offset line " << (start.line() + 1);
      if (end.line() > start.line())
        output << ", column " << (start.column() + 1) << " to line "
               << (end.line() + 1) << ", column" << end.column();
      else if (end.column() > start.column() + 1)
        output << ", columns " << (start.column() + 1) << " to "
               << end.column();
      else
        output << ", column " << (start.column() + 1);
      output << ":\n";
      return output.str();

    case ast::SourceLocation::SOURCE_NOT_SET:
      break;
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << "Invalid source case: " << start.DebugString();
}

// Returns a string that quotes and marks the given source location interval,
// e.g.:
//
//  | hdr.ethernet.eth_type == 0x08 ->
// 8|   1+2 == true
//  |   ^^^^^^^^^^^
// TODO(b/243082448): Add multiline quoting. Not urgent as current uses only
// quote single lines.
absl::StatusOr<std::string> Quote(const ConstraintSource& constraint,
                                  const ast::SourceLocation& start,
                                  const ast::SourceLocation& end) {
  if (gutils::ProtoEqual(start, end)) return "";

  std::stringstream constraint_string(constraint.constraint_string);

  // Index of the line we want to quote.
  const int kKeyLine = start.line();
  // Start and end are located relative to a source file/table. Offset is the
  // relative location of constraint to that same source.
  const int kOffset = constraint.constraint_location.line();
  // Number of lines to show before the key line, for context.
  const int kBefore = (start.line() == kOffset) ? 0 : 1;

  // Discard unneeded lines before the lines we're interested in.
  int i = kOffset;
  for (std::string line; i < kKeyLine - kBefore; i++) {
    if (!std::getline(constraint_string, line)) {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC) << absl::StrFormat(
                 "Interval [`start`, `end`] to quote must lie within given "
                 "`constraint`, but `start.line()` = %d while the final line "
                 "of `constraint` is %d",
                 kKeyLine, i - 1);
    }
  }

  const std::string key_line_margin = std::to_string(kKeyLine + 1);
  const std::string context_line_margin(key_line_margin.size(), ' ');
  const std::string separator = " | ";
  std::stringstream output;

  // Output lines before key line for context.
  for (std::string line; i < kKeyLine; i++) {
    if (std::getline(constraint_string, line)) {
      output << context_line_margin << separator << line << "\n";
    } else {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC) << absl::StrFormat(
                 "Interval [`start`, `end`] to quote must lie within given "
                 "`constraint`, but `start.line()` = %d while the final line "
                 "of `constraint` is %d",
                 kKeyLine, i - 1);
    }
  }
  // Output key line.
  std::string line;
  if (std::getline(constraint_string, line)) {
    output << key_line_margin << separator << line << "\n";
  } else {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC) << absl::StrFormat(
               "Interval [`start`, `end`] to quote must lie within given "
               "`constraint`, but `start.line()` = %d while the final line "
               "of `constraint` is %d",
               kKeyLine, i - 1);
  }

  // Mark key columns using '^'.
  const std::string margin = absl::StrCat(context_line_margin, separator,
                                          std::string(start.column(), ' '));
  const int marker_size = (start.line() == end.line())
                              ? (end.column() - start.column())
                              : (line.size() - margin.size());
  const std::string marker(marker_size, '^');
  output << margin << marker << "\n";
  return output.str();
}
}  // namespace

std::string GetSourceName(const ast::SourceLocation& source) {
  switch (source.source_case()) {
    case ast::SourceLocation::kTableName:
      return source.table_name();
    case ast::SourceLocation::kFilePath:
      return source.file_path();
    case ast::SourceLocation::kActionName:
      return source.action_name();
    case ast::SourceLocation::SOURCE_NOT_SET:
      break;
  }
  LOG(ERROR) << "Invalid ast::SourceLocation type: " << source.DebugString();
  return "Unknown Source Type";
}

absl::StatusOr<std::string> QuoteSubConstraint(
    const ConstraintSource& constraint, const ast::SourceLocation& from,
    const ast::SourceLocation& to) {
  if (!ast::HaveSameSource(constraint.constraint_location, from) ||
      !ast::HaveSameSource(constraint.constraint_location, to) ||
      !ast::HaveSameSource(from, to)) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC) << absl::StrFormat(
               "Quoting of multi-source locations not allowed. Constraint-"
               "Source: %s From-Source: %s To-Source: %s",
               GetSourceName(constraint.constraint_location),
               GetSourceName(from), GetSourceName(to));
  }
  ASSIGN_OR_RETURN(std::string explanation, Explain(from, to));
  ASSIGN_OR_RETURN(std::string quote, Quote(constraint, from, to));
  return absl::StrCat(explanation, quote);
}

}  // namespace p4_constraints
