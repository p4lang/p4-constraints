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

// Module for quoting and highlighting a location in a source file.

#ifndef P4_CONSTRAINTS_QUOTE_H_
#define P4_CONSTRAINTS_QUOTE_H_

#include <string>

#include "p4_constraints/ast.pb.h"

namespace p4_constraints {

// Returns string that describes and -- if possible -- quotes the given source
// interval. E.g., for
//   start = { line: 7, column: 2, source: { file_path: "my/input/file" } }
//   end = { line: 7, column: 13, source: { file_path: "my/input/file" } }
// QuoteSourceLocation(start, end) may produce the following output:
//
// my/input/file:8:3-13:
//   | hdr.ethernet.eth_type == 0x08 ->
// 8 |   1+2 == true
//   |   ^^^^^^^^^^^
std::string QuoteSourceLocation(const ast::SourceLocation& start,
                                const ast::SourceLocation& end);
}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_QUOTE_H_
