// This file provides tools for symbolically representing table entries that
// satisfy a given p4-constraint, and for synthesizing them into concrete table
// entries.

/*
 * Copyright 2023 The P4-Constraints Authors
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

#ifndef P4_CONSTRAINTS_BACKEND_SYMBOLIC_INTERPRETER_H_
#define P4_CONSTRAINTS_BACKEND_SYMBOLIC_INTERPRETER_H_

#include <variant>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "gutils/overload.h"
#include "p4_constraints/backend/constraint_info.h"
#include "z3++.h"

namespace p4_constraints {

// -- Symbolic Types -----------------------------------------------------------

// Represents a p4::v1::FieldMatch::Exact symbolically.
struct SymbolicExact {
  // Bitvector of width N (where N is the bitwidth of the match key).
  z3::expr value;
};

// Represents a p4::v1::FieldMatch::Ternary and p4::v1::FieldMatch::Optional
// symbolically. Used to represent both ternary and optional keys, since an
// optional key is just a ternary key whose mask is all zeros or all ones.
struct SymbolicTernary {
  // Bitvectors of width N (where N is the bitwidth of the match key).
  z3::expr value;
  z3::expr mask;
};

// Represents a p4::v1::FieldMatch::Lpm symbolically.
struct SymbolicLpm {
  // Bitvector of width N (where N is the bitwidth of the match key).
  z3::expr value;
  // Integer between 0 and N (where N is the bitwidth of the match key).
  // TODO(b/292552944): If necessary, investigate whether using a bitvector as a
  // mask causes significant improvements compared to the integer prefix length
  // representation.
  z3::expr prefix_length;
};

// Z3 representation of a single match key in a P4 table entry.
using SymbolicKey = std::variant<SymbolicExact, SymbolicTernary, SymbolicLpm>;

// -- Main Functions -----------------------------------------------------------

// Creates a `SymbolicKey` that symbolically represents the match field key
// given by `key` in Z3 and adds the match to the context in `solver`. Also adds
// two forms of well-formedness constraints for that `key`:
// 1) Domain constraints, enforcing the bitwidth of the various `value`s and the
//    allowed values for `prefix_length` (for LPMs) and `mask` (for optionals).
// 2) Canonicity constraints, enforcing that `value`s and their `mask`s or
//    `prefix_length`s correspond to ensure compatibility with P4Runtime. E.g.
//    on a switch, the following value and mask pairs behave identically, but we
//    disallow the second with canonicity constraints:
//    - 10 & 10
//    - 11 & 10
//    This is required to concretize symbolic keys to valid P4Runtime keys that
//    still satisfy any p4-constraints.
//
// Expects `key` to have a non-zero bitwidth.
absl::StatusOr<SymbolicKey> AddSymbolicKey(const KeyInfo& key,
                                           z3::solver& solver);

// -- Accessors ----------------------------------------------------------------

// Gets the Z3 expression in the `value` field of `symbolic_key`.
absl::StatusOr<z3::expr> GetValue(const SymbolicKey& symbolic_key);

// Gets the Z3 expression in the `mask` field of `symbolic_key`, if it is an
// optional or ternary. Otherwise, returns an InvalidArgumentError.
absl::StatusOr<z3::expr> GetMask(const SymbolicKey& symbolic_key);

// Gets the Z3 expression in the `prefix_length` field of `symbolic_key`, if it
// is an LPM. Otherwise, returns an InvalidArgumentError.
absl::StatusOr<z3::expr> GetPrefixLength(const SymbolicKey& symbolic_key);

// -- Pretty Printers ----------------------------------------------------------

template <typename Sink>
void AbslStringify(Sink& sink, const SymbolicExact& exact) {
  absl::Format(&sink, "SymbolicExact{ value: '%s' }", exact.value.to_string());
}

template <typename Sink>
void AbslStringify(Sink& sink, const SymbolicTernary& ternary) {
  absl::Format(&sink, "SymbolicTernary{ value: '%s' mask: '%s' }",
               ternary.value.to_string(), ternary.mask.to_string());
}

template <typename Sink>
void AbslStringify(Sink& sink, const SymbolicLpm& lpm) {
  absl::Format(&sink, "SymbolicLpm{ value: '%s' prefix_length: '%s' }",
               lpm.value.to_string(), lpm.prefix_length.to_string());
}

template <typename Sink>
void AbslStringify(Sink& sink, const SymbolicKey& symbolic_key) {
  return std::visit(
      gutils::Overload{
          [&](const auto& variant) { absl::Format(&sink, "%v", variant); },
      },
      symbolic_key);
}

inline std::ostream& operator<<(std::ostream& os, const SymbolicKey& key) {
  return os << absl::StrCat(key);
}

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_BACKEND_SYMBOLIC_INTERPRETER_H_
