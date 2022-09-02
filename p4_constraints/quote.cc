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

#include "p4_constraints/quote.h"

#include <fstream>
#include <sstream>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "glog/logging.h"
#include "gutils/status_macros.h"
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
      break;

    case ast::SourceLocation::kFilePath:
      // Succinct mode: path/to/file:line:column.
      output << start.file_path() << ":" << (start.line() + 1) << ":"
             << (start.column() + 1);
      if (end.line() > start.line())
        output << "-" << (end.line() + 1) << ":" << end.column();
      else if (end.column() > start.column() + 1)
        output << "-" << end.column();
      break;

    default:
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "unknown source case: " << start.source_case();
  }
  output << ":\n";
  return output.str();
}

// Returns a string that quotes and marks the given source location interval,
// e.g.:
//
//  | hdr.ethernet.eth_type == 0x08 ->
// 8|   1+2 == true
//  |   ^^^^^^^^^^^
// TODO(b/242908850): Remove this overload and migrate parser/lexer/typechecker
// to the other overload of this function.
std::string Quote(const ast::SourceLocation& start,
                  const ast::SourceLocation& end) {
  if (start.source_case() != ast::SourceLocation::kFilePath) return "";
  if (start.file_path() != end.file_path()) return "";
  std::ifstream file(start.file_path());
  if (!file.is_open()) return "";

  // Index of the line we want to quote.
  const int key_line = start.line();
  // Number of lines to show before the key line, for context.
  static const int kBefore = 1;

  // Discard unneeded lines before the lines we're interested in.
  int i = 0;
  for (std::string line; i < key_line - kBefore; i++) {
    if (!std::getline(file, line)) return "";
  }

  const std::string key_line_margin = std::to_string(key_line + 1);
  const std::string context_line_margin(key_line_margin.size(), ' ');
  const std::string separator = " | ";
  std::stringstream output;

  // Output lines before key line for context.
  for (std::string line; i < key_line; i++) {
    if (std::getline(file, line))
      output << context_line_margin << separator << line << "\n";
    else
      return "";
  }
  // Output key line.
  std::string line;
  if (std::getline(file, line))
    output << key_line_margin << separator << line << "\n";
  else
    return "";

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
    if (!std::getline(constraint_string, line))
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC) << absl::StrFormat(
                 "Interval [`start`, `end`] to quote must lie within given "
                 "`constraint`, but "
                 "`start.line()` = %d while the final line of `constraint` is "
                 "%d",
                 kKeyLine, i - 1);
  }

  const std::string key_line_margin = std::to_string(kKeyLine + 1);
  const std::string context_line_margin(key_line_margin.size(), ' ');
  const std::string separator = " | ";
  std::stringstream output;

  // Output lines before key line for context.
  for (std::string line; i < kKeyLine; i++) {
    if (std::getline(constraint_string, line))
      output << context_line_margin << separator << line << "\n";
    else
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC) << absl::StrFormat(
                 "Interval [`start`, `end`] to quote must lie within given "
                 "`constraint`, "
                 "`start.line()` = %d while the final line of `constraint` is "
                 "%d",
                 kKeyLine, i - 1);
  }
  // Output key line.
  std::string line;
  if (std::getline(constraint_string, line))
    output << key_line_margin << separator << line << "\n";
  else
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC) << absl::StrFormat(
               "Interval [`start`, `end`] to quote must lie within given "
               "`constraint`, "
               "`start.line()` = %d while the final line of `constraint` is "
               "%d",
               kKeyLine, i - 1);

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
    default:
      return "Unknown Source Type";
  }
}

std::string QuoteSourceLocation(const ast::SourceLocation& start,
                                const ast::SourceLocation& end) {
  if (start.file_path() != end.file_path() ||
      start.table_name() != end.table_name()) {
    LOG(ERROR) << "Quoting of multi-source locations not implemented. "
               << "Omitting source location.";
    return "";
  }
  absl::StatusOr<std::string> explanation = Explain(start, end);
  if (!explanation.ok()) return "";
  return absl::StrCat(*explanation, Quote(start, end));
}

absl::StatusOr<std::string> QuoteSubConstraint(
    const ConstraintSource& constraint, const ast::SourceLocation& from,
    const ast::SourceLocation& to) {
  if (constraint.constraint_location.file_path() != to.file_path() ||
      constraint.constraint_location.table_name() != to.table_name() ||
      constraint.constraint_location.file_path() != from.file_path() ||
      constraint.constraint_location.table_name() != from.table_name() ||
      from.file_path() != to.file_path() ||
      from.table_name() != to.table_name()) {
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
