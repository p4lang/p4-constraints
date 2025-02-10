/*
 * Copyright 2023 The P4-Constraints Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_BACKEND_ERRORS_H_
#define THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_BACKEND_ERRORS_H_

#include "gutils/status_builder.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"

namespace p4_constraints {

// Returns an InternalError for a runtime type mismatch with in-depth,
// human-readable source information. Should only be used for expressions that
// are known to be type-checked since this makes it an InternalError.
gutils::StatusBuilder RuntimeTypeError(const ConstraintSource& source,
                                       const ast::SourceLocation& start,
                                       const ast::SourceLocation& end);
}  // namespace p4_constraints

#endif  // THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_BACKEND_ERRORS_H_
