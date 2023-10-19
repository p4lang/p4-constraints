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

#ifndef P4_CONSTRAINTS_FRONTEND_PARSER_H_
#define P4_CONSTRAINTS_FRONTEND_PARSER_H_

#include <vector>

#include "absl/status/statusor.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/frontend/constraint_kind.h"
#include "p4_constraints/frontend/token.h"

namespace p4_constraints {

// Generates AST from `source`. Returns Error Status if constraint is rejected
// by grammar, providing contextual quote pulled from `source`.
absl::StatusOr<ast::Expression> ParseConstraint(ConstraintKind constraint_kind,
                                                const ConstraintSource& source);

// -- END OF PUBLIC INTERFACE --------------------------------------------------

// Exposed for testing only.
namespace internal_parser {

// Generates AST from `tokens`. Returns Error Status if constraint is rejected
// by grammar. Allows testing parser independently from lexer.
absl::StatusOr<ast::Expression> ParseConstraint(
    ConstraintKind constraint_kind, const std::vector<Token>& tokens,
    const ConstraintSource& source);

}  // namespace internal_parser

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_FRONTEND_PARSER_H_
