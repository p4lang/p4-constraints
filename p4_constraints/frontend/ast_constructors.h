/*
 * Copyright 2020 The P4-Constraints Authors
 * SPDX-License-Identifier: Apache-2.0
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

// This module abstracts the constructors needed to build an AST, allowing the
// parser implementation to be oblivious of the AST representation.

#ifndef P4_CONSTRAINTS_FRONTEND_AST_CONSTRUCTORS_H_
#define P4_CONSTRAINTS_FRONTEND_AST_CONSTRUCTORS_H_

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/frontend/constraint_kind.h"
#include "p4_constraints/frontend/token.h"

namespace p4_constraints {
namespace ast {

// Returns an AST given a TRUE or FALSE token, or an error Status otherwise.
absl::StatusOr<ast::Expression> MakeBooleanConstant(const Token& boolean);

// Returns an AST given a BINARY/OCTARY/DECIMAL/HEXADEC token, or an error
// Status otherwise.
absl::StatusOr<ast::Expression> MakeIntegerConstant(const Token& numeral);

// Returns an AST `a` such that `a.integer_constant() == net(address)`. Valid
// values for address_type (`net`) are "ipv4", "ipv6", or "mac". Returns error
// if address_type is invalid. The address_string (`address`) is the IPv4, IPv6
// or MAC address string. The start_location of the AST is the ID token's start
// location and the end location of the AST is the RPAR token's end location as
// the Tokens (ID, LPAR, STRING, RPAR) are expressed as an integer constant.
absl::StatusOr<ast::Expression> MakeNetworkAddressIntegerConstant(
    const absl::string_view& address_type,
    const absl::string_view& address_string,
    const ast::SourceLocation& start_location,
    const ast::SourceLocation& end_location);

// Returns an AST for table entry attribute access (such as ::priority).
absl::StatusOr<ast::Expression> MakeAttributeAccess(
    const Token& double_colon, const Token& attribute_name);

// Returns an AST `a` such that `a.param() == "id1id2...idn"` (if parsing action
// parameters) and `a.key() == "id1.id2...idn"` (if parsing keys) given ID
// tokens `{t1, ..., tn}` such that `idi == ti.text`, or an error Status
// otherwise.
absl::StatusOr<ast::Expression> MakeVariable(absl::Span<const Token> tokens,
                                             ConstraintKind constraint_kind);

// Returns an AST (with the given operand) when given a BANG ('!') token,
// or an error Status otherwise.
absl::StatusOr<ast::Expression> MakeBooleanNegation(const Token& bang_token,
                                                    ast::Expression operand);

// Returns an AST (with the given operand) when given a MINUS ('-') token,
// or an error Status otherwise.
absl::StatusOr<ast::Expression> MakeArithmeticNegation(const Token& minus_token,
                                                       ast::Expression operand);

// Returns an AST (with the given operands) when given  a AND, OR, or IMPLIES
// token, or an error Status otherwise.
absl::StatusOr<ast::Expression> MakeBinaryExpression(const Token& binop_token,
                                                     ast::Expression left,
                                                     ast::Expression right);

// Returns an AST when given an ID token `field`, or an error Status otherwise.
absl::StatusOr<ast::Expression> MakeFieldAccess(ast::Expression expr,
                                                const Token& field);

}  // namespace ast
}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_FRONTEND_AST_CONSTRUCTORS_H_
