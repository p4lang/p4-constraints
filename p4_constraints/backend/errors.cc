// Copyright 2023 The P4-Constraints Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include "p4_constraints/backend/errors.h"

#include <string>

#include "absl/status/statusor.h"
#include "gutil/status.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/quote.h"

namespace p4_constraints {

gutil::StatusBuilder RuntimeTypeError(const ConstraintSource& source,
                                      const ast::SourceLocation& start,
                                      const ast::SourceLocation& end) {
  absl::StatusOr<std::string> quote = QuoteSubConstraint(source, start, end);
  if (!quote.ok()) {
    return gutil::InternalErrorBuilder()
           << "Failed to quote sub-constraint: "
           << gutil::StableStatusToString(quote.status());
  }
  return gutil::InternalErrorBuilder() << *quote << "Runtime type error: ";
}

}  // namespace p4_constraints
