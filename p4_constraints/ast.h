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

// Provides auxiliary functions for the types defined in ast.proto.

#ifndef P4_CONSTRAINTS_AST_H_
#define P4_CONSTRAINTS_AST_H_

#include <iosfwd>
#include <optional>
#include <string>

#include "absl/types/optional.h"
#include "p4_constraints/ast.pb.h"

namespace p4_constraints {
namespace ast {

// -- Source Locations ---------------------------------------------------------

bool operator==(const SourceLocation& left, const SourceLocation& right);
std::ostream& operator<<(std::ostream& os, const SourceLocation& location);

// -- Types --------------------------------------------------------------------

// Type equality.
bool operator==(const Type& left, const Type& right);

// Returns human readable name of the given type.
std::string TypeName(const Type& type);

// Writes human readable name of the given type to the output stream.
std::ostream& operator<<(std::ostream& os, const Type& type);

// True iff values of the given type support ordered comparison (<, <=, >, >=).
bool TypeHasOrdering(const Type& type);

// Returns bit-width of the given type, provided the type is fixed-size.
absl::optional<int> TypeBitwidth(const Type& type);

// Sets bitwidth of the given type, provided the type is fixed-size, or does
// nothing otherwise. Returns `true` in the former case and `false` in the
// latter case.
bool SetTypeBitwidth(Type* type, int bitwidth);

// Returns Type `t` such that `t.type_case () == type_case`, leaving all fields
// of `t` such as `t.bitwidth` uninitialized.
Type TypeCaseToType(Type::TypeCase type_case);

}  // namespace ast
}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_AST_H_
