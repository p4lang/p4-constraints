/*
 * Copyright 2020 The P4-Constraints Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Tokens are produced by the lexer and consumed by the parser.

#ifndef P4_CONSTRAINTS_FRONTEND_TOKEN_H_
#define P4_CONSTRAINTS_FRONTEND_TOKEN_H_

#include <iosfwd>
#include <string>

#include "absl/types/optional.h"
#include "p4_constraints/ast.pb.h"

namespace p4_constraints {

// A token is a sequence of characters with an assigned meaning.
struct Token {
 public:
  enum Kind {
    TRUE,            // "true"
    FALSE,           // "false"
    BANG,            // "!"
    AND,             // "&&"
    OR,              // "||"
    IMPLIES,         // "->"
    MINUS,           // "-"
    DOT,             // "."
    DOUBLE_COLON,    // "::"
    SEMICOLON,       // ";"
    EQ,              // "=="
    NE,              // "!="
    GT,              // ">"
    GE,              // ">="
    LT,              // "<"
    LE,              // "<="
    LPAR,            // "("
    RPAR,            // ")"
    ID,              // identifier: [_a-zA-Z][_a-zA-Z_0-9]*
    BINARY,          // binary numeral: 0[bB](0..1)+
    OCTARY,          // octary numeral: 0[oO](0..7)+
    DECIMAL,         // decimal numeral: 0..9+ or 0[dD](0..9)+
    HEXADEC,         // hexadecimal numeral: 0[xX](0..9|[a-fA-F])+
    END_OF_INPUT,    // indicates that the end of the input was reached
    UNEXPECTED_CHAR  // indicates that an unexpected character was encountered
    // Invariant: UNEXPECTED_CHAR must always be the last (maximum) kind.
  };

  // All token kinds. Keep in sync with enum Kind.
  static const Kind kAllKinds[25];

  Token(const Kind kind, const std::string text,
        const ast::SourceLocation start_location,
        const ast::SourceLocation end_location) noexcept
      : kind{kind},
        text{text},
        start_location{start_location},
        end_location{end_location} {};

  const Kind kind;

  // Text read by lexer when generating this token.
  const std::string text;

  // The source location of the text read to generate this token is the
  // half-open, 0-based interval [start_location, end_location).
  const ast::SourceLocation start_location;
  const ast::SourceLocation end_location;

  // Mappings from token kinds to keywords and vice versa. For tokens
  // corresponding to several string such as BINARY, the corresponding keyword
  // is bracketed as in "<BINARY>".
  static std::string KindToKeyword(Kind token_kind);
  static absl::optional<Kind> KeywordToKind(const std::string& keyword);
};

std::ostream& operator<<(std::ostream& os, Token::Kind kind);

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_FRONTEND_TOKEN_H_
