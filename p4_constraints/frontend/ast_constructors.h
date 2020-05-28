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

// This module abstracts the constructors needed to build an AST, allowing the
// parser implementation to be oblivious of the AST representation.

#ifndef P4_CONSTRAINTS_FRONTEND_AST_CONSTRUCTORS_H_
#define P4_CONSTRAINTS_FRONTEND_AST_CONSTRUCTORS_H_

#include "p4_constraints/ast.pb.h"
#include "p4_constraints/frontend/token.h"
#include "absl/types/span.h"
#include "util/statusor.h"

namespace p4_constraints {
namespace ast {

// Returns an AST given a TRUE or FALSE token, or an error Status otherwise.
util::StatusOr<ast::Expression> MakeBooleanConstant(Token boolean);

// Returns an AST given a BINARY/OCTARY/DECIMAL/HEXADEC token, or an error
// Status otherwise.
util::StatusOr<ast::Expression> MakeIntegerConstant(Token numeral);

// Returns an AST `a` such that `a.key() == "id1.id2...idn"` if given ID tokens
// `{t1, ..., tn}` such that `idi == ti.text`, or an error Status otherwise.
util::StatusOr<ast::Expression> MakeKey(absl::Span<const Token> key_fragments);

// Returns an AST (with the given operand) when given a BANG ('!') token,
// or an error Status otherwise.
util::StatusOr<ast::Expression> MakeBooleanNegation(Token bang_token,
                                                    ast::Expression operand);

// Returns an AST (with the given operand) when given a MINUS ('-') token,
// or an error Status otherwise.
util::StatusOr<ast::Expression> MakeArithmeticNegation(Token minus_token,
                                                       ast::Expression operand);

// Returns an AST (with the given operands) when given  a AND, OR, or IMPLIES
// token, or an error Status otherwise.
util::StatusOr<ast::Expression> MakeBinaryExpression(Token binop_token,
                                                     ast::Expression left,
                                                     ast::Expression right);

// Returns an AST when given an ID token `field`, or an error Status otherwise.
util::StatusOr<ast::Expression> MakeFieldAccess(ast::Expression expr,
                                                Token field);

}  // namespace ast
}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_FRONTEND_AST_CONSTRUCTORS_H_
