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

// The lexer turns an input string into a sequence of tokens.
//
// Known limitation: When the lexer returns an UNEXPECTED_CHAR token, the
// location of that token points at the first character in a sequence of
// characters that do not constitute a token, rather than the actual first
// unexpected character. For example, consider the following input:
//
//    true |& more stuff    --tokenize-->    TRUE, UNEXPECTED_CHAR('|')
//         ^
// The lexer will emit a TRUE token followed by an UNEXPECTED_CHAR token
// pointing at '|', as indicated above. It would be better to point at '&',
// since replacing '&' with '|' makes the input lexable.
//
// This is due to a limitation of RE2 (see yaqs/6274189471383552), which cannot
// compute the prefix-closure of a given regexp for us currently. This could be
// easily fixed by hard-coding the prefix closure by hand, or better, submit a
// pull request to RE2 -- but currently this seems not worth the effort.

#ifndef P4_CONSTRAINTS_FRONTEND_LEXER_H_
#define P4_CONSTRAINTS_FRONTEND_LEXER_H_

#include <vector>

#include "p4_constraints/ast.pb.h"
#include "p4_constraints/frontend/token.h"
#include "re2/stringpiece.h"

namespace p4_constraints {

// Turns the input string into a sequence of tokens. Note that this function
// is total; syntax errors are signaled by emitting an UNEXPECTED_CHAR token.
// The final token in the returned token sequence is guaranteed to be an
// END_OF_INPUT or UNEXPECTED_CHAR token.
std::vector<Token> Tokenize(re2::StringPiece input,
                            ast::SourceLocation start_location);

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_FRONTEND_LEXER_H_
