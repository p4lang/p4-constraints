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

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"

namespace p4_constraints {

// Returns a string that quotes a sub-constraint within `constraint` and
// describes its source location, delimited by `from` and `to`. If delimiters
// fall out of range or args are malformed, returns an invalid argument error.
absl::StatusOr<std::string> QuoteSubConstraint(
    const ConstraintSource& constraint, const ast::SourceLocation& from,
    const ast::SourceLocation& to);

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_QUOTE_H_
