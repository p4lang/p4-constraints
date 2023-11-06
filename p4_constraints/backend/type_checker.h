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

// The type checker infers and checks the types of expressions.

#ifndef P4_CONSTRAINTS_BACKEND_TYPE_CHECKER_H_
#define P4_CONSTRAINTS_BACKEND_TYPE_CHECKER_H_

#include "absl/status/status.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"

namespace p4_constraints {

// Type checks the given expression, returning an OkStatus if type checking
// succeeds or an InvalidInput Status otherwise.
//
// Note that this is a side-effecting operation that may mutate the given
// expression in two ways:
// - It may mutate the type of the expression and its subexpressions, filling in
//   the correct types.
// - It may insert type-casts, making implicit casts explicit.
//
// Upon successful completion of these functions, the given expression is
// guaranteed to contain no ast::Type::Unknown/Unsupported types.
//
// These functions should not be called on an `expr` that has already been type
// checked (more specifically, on an `expr` that already contains type casts).
// Doing so will result in an InvalidInput Error.
absl::Status InferAndCheckTypes(ast::Expression* expr,
                                const TableInfo& table_info);
absl::Status InferAndCheckTypes(ast::Expression* expr,
                                const ActionInfo& action_info);

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_BACKEND_TYPE_CHECKER_H_
