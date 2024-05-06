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

#include "p4_constraints/frontend/lexer.h"

#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/string_view.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/frontend/token.h"
#include "re2/re2.h"

namespace p4_constraints {

namespace {

// Consumes characters from the input until the string "*/" appears or the input
// is exhausted, updating the given SourceLocation accordingly.
void SwallowMultiLineComment(absl::string_view* input,
                             ast::SourceLocation* location) {
  static const LazyRE2 kCommentRegexp{
      // Important: the ordering matters, since the first matching case applies!
      "(\\*/)"                // End of comment ('*/').
      "|([^\\n\\r\\*]+|\\*)"  // Comment fragment; safe to accept '*' since '*/'
                              // (first case) did not match.
      "|((?:\\r\\n?)|\\n)"    // Newline.
  };
  absl::string_view end_of_comment = "";
  absl::string_view comment = "";
  absl::string_view newline = "";
  while (RE2::Consume(input, *kCommentRegexp, &end_of_comment, &comment,
                      &newline)) {
    if (!end_of_comment.empty()) {
      location->set_column(location->column() + end_of_comment.size());
      return;
    } else if (!comment.empty()) {
      location->set_column(location->column() + comment.size());
    } else if (!newline.empty()) {
      location->set_line(location->line() + 1);
      location->set_column(0);
    } else {
      LOG(ERROR) << "impossible: no capture group matched in string: " << input;
    }
  }
  DCHECK(input->empty());
  // TODO(smolkaj): We tolerate unterminated comments that run until the end of
  // the input. It would be cleaner to report a lex error but this would
  // require a redesign since the lexer is currently pure, i.e. not in the
  // StatusOr monad. Not worth the effort at the moment.
}

// Specifies what constitutes a token.
// Important: the ordering matters, since the first matching case applies!
const LazyRE2 kTokenPattern{
    // clang-format off
    "(?P<whitespace>[ \\t]+)"
    "|(?P<newline>(?:\\r\\n?)|\\n)"
    "|(?P<comment>//[^\\r\\n]*)"
    "|(?P<begin_multiline_comment>/\\*)"
    // Keywords.
    "|(?P<keyword>"
      "true|false|&&"
      "|\\|\\|"
      "|->"
      "|::"
      "|==|!=|>=|<="
      "|[!()><.;\\-]"
    ")"
    // IDs.
    "|(?P<id>[_a-zA-Z][_a-zA-Z0-9]*)"
    // Numerals.
    "|(?:0[bB])" "(?P<binary>[0-1]+)"
    "|(?:0[oO])" "(?P<octary>[0-7]+)"
    "|(?:0[xX])" "(?P<hexadec>[0-9a-fA-F]+)"
    "|(?:0[dD])?" "(?P<decimal>[0-9]+)"
    // Strings.
    "|(?P<string>'([^']*)')"
    // clang-format on
};

// Access capture group in kTokenPattern by name.
absl::string_view CaptureByName(
    const std::string& group_name,
    const std::vector<absl::string_view>& captures) {
  auto iter = kTokenPattern->NamedCapturingGroups().find(group_name);
  if (iter != kTokenPattern->NamedCapturingGroups().end()) {
    return captures[iter->second];
  } else {
    LOG(ERROR) << "non-existent capture group: " << group_name;
    return "";
  }
}

}  // namespace

std::vector<Token> Tokenize(const ConstraintSource& constraint) {
  // Output.
  std::vector<Token> tokens;
  // Input
  absl::string_view input = constraint.constraint_string;
  // Location tracking.
  ast::SourceLocation start_location = constraint.constraint_location;
  ast::SourceLocation current_location = start_location;

  // +1 because there is an implicit capturing group at index 0 corresponding to
  // the entire regexp.
  const int capture_count = kTokenPattern->NumberOfCapturingGroups() + 1;

  // We will have RE2 store the strings matched by each capturing group here.
  std::vector<absl::string_view> captures(capture_count);

  while (kTokenPattern->Match(input, 0, input.size(), RE2::Anchor::ANCHOR_START,
                              captures.data(), capture_count)) {
    // The next token starts at the current location.
    DCHECK_EQ(start_location, current_location) << "loop invariant violated";

    // Consume matched input (aka "lexeme").
    std::string lexeme = std::string(captures[0]);
    input.remove_prefix(lexeme.length());

    // Advance location.
    current_location.set_column(current_location.column() + lexeme.length());

    // Which kind of token did we find?
    Token::Kind kind;
    if (!CaptureByName("whitespace", captures).empty() ||
        !CaptureByName("comment", captures).empty()) {
      start_location = current_location;
      continue;
    } else if (!CaptureByName("newline", captures).empty()) {
      current_location.set_line(current_location.line() + 1);
      current_location.set_column(0);
      start_location = current_location;
      continue;
    } else if (!CaptureByName("begin_multiline_comment", captures).empty()) {
      SwallowMultiLineComment(&input, &current_location);
      start_location = current_location;
      continue;
    } else if (!CaptureByName("keyword", captures).empty()) {
      kind = Token::KeywordToKind(lexeme).value_or(Token::UNEXPECTED_CHAR);
      if (kind == Token::UNEXPECTED_CHAR)
        LOG(ERROR)
            << "keyword " << lexeme
            << " recognized by lexer, but unknown to Token::KeywordToKind";
    } else if (!CaptureByName("id", captures).empty()) {
      kind = Token::ID;
      // For numerals, update lexeme to exclude base prefix (e.g., "0b")
    } else if (!CaptureByName("binary", captures).empty()) {
      // Update lexeme to exclude base prefix.
      lexeme = std::string(CaptureByName("binary", captures));
      kind = Token::BINARY;
    } else if (!CaptureByName("octary", captures).empty()) {
      // Update lexeme to exclude base prefix.
      lexeme = std::string(CaptureByName("octary", captures));
      kind = Token::OCTARY;
    } else if (!CaptureByName("decimal", captures).empty()) {
      // Update lexeme to exclude base prefix.
      lexeme = std::string(CaptureByName("decimal", captures));
      kind = Token::DECIMAL;
    } else if (!CaptureByName("hexadec", captures).empty()) {
      // Update lexeme to exclude base prefix.
      lexeme = std::string(CaptureByName("hexadec", captures));
      kind = Token::HEXADEC;
    } else if (!CaptureByName("string", captures).empty()) {
      lexeme = std::string(CaptureByName("string", captures));
      lexeme = lexeme.substr(1, lexeme.size() - 2);
      kind = Token::STRING;
    } else {
      LOG(ERROR) << "impossible: no capture group matched in string: "
                 << lexeme;
      kind = Token::UNEXPECTED_CHAR;
    }
    tokens.push_back(Token(kind, lexeme, start_location, current_location));
    // Advance start location.
    start_location = current_location;
  }

  // No match - input does no longer begin with a token.
  if (input.empty()) {
    tokens.push_back(
        Token(Token::END_OF_INPUT, "", start_location, current_location));
  } else {
    // Advance location by one column to make the location interval non-empty.
    current_location.set_column(current_location.column() + 1);
    // TODO(smolkaj): We could do a better job reporting the precise location of
    // the first unexpected character here, see "Known limitation" in lexer.h.
    tokens.push_back(Token(Token::UNEXPECTED_CHAR, {input[0]}, start_location,
                           current_location));
  }

  return tokens;
}

}  // namespace p4_constraints
