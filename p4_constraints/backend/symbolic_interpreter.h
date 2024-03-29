// This file provides tools for symbolically representing table entries that
// satisfy a given p4-constraint, and for synthesizing them into concrete table
// entries.
//
// Currently, a Z3 solver used with this API may only encode a single table
// entry at a time.

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

#include <functional>
#include <ostream>
#include <string>
#include <variant>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "gutils/overload.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/constraint_source.h"
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

// Currently, the only symbolic attribute supported is priority.
struct SymbolicAttribute {
  z3::expr value;
};

constexpr char kSymbolicPriorityAttributeName[] = "priority";

// Z3 representation of a single match key in a P4 table entry.
using SymbolicKey = std::variant<SymbolicExact, SymbolicTernary, SymbolicLpm>;

struct SymbolicEnvironment {
  absl::flat_hash_map<std::string, SymbolicKey> symbolic_key_by_name;
  absl::flat_hash_map<std::string, SymbolicAttribute>
      symbolic_attribute_by_name;
};

// -- Main Functions -----------------------------------------------------------

// Adds sufficient symbolic constraints to `solver` to represent an entry for
// `table` that respects its P4-Constraints and is well-formed according to the
// P4Runtime specification.
// Specifically, populates `solver` with all of the keys from `table` aside from
// those skipped through `skip_key_named`. Also adds well-formedness constraints
// (further described at the `AddSymbolicKey` function below) for each key and
// Z3 versions of any p4-constraints given by `table.constraints`. If the
// P4Runtime standard requires the table's entries to have a priority (i.e.
// because at least one key is either Optional or Ternary), then a symbolic
// priority with well-formedness constraints is also added. Returns a
// SymbolicEnvironment mapping the names of all symbolic variables to their
// symbolic expression counterparts.
// NOTE: This API will only encode a single table entry (as opposed to multiple)
// for a given `solver`. In other words, it is NOT possible to encode
// constraints for multiple entries by calling this function more than once with
// the same `solver`.
absl::StatusOr<SymbolicEnvironment> EncodeValidTableEntryInZ3(
    const TableInfo& table, z3::solver& solver,
    std::function<absl::StatusOr<bool>(absl::string_view key_name)>
        skip_key_named = [](absl::string_view key_name) { return false; });

// Returns an entry for the table given by `table_info` derived from `model`.
// All keys named in `table_info` must be mapped by
// `environment.symbolic_key_by_name` unless `skip_key_named(name)` holds for
// the key `name`. NOTE: The entry will NOT contain an action and is thus not a
// valid P4Runtime entry without modification.
// NOTE: This API expects the `model` to represent a single table entry (as
// opposed to multiple). This can be achieved by a call to
// `EncodeValidTableEntryInZ3`.
// TODO(b/242201770): Extract actions once action constraints are supported.
absl::StatusOr<p4::v1::TableEntry> ConcretizeEntry(
    const z3::model& model, const TableInfo& table_info,
    const SymbolicEnvironment& environment,
    std::function<absl::StatusOr<bool>(absl::string_view key_name)>
        skip_key_named = [](absl::string_view key_name) { return false; });

// -- Accessors ----------------------------------------------------------------

// Gets the Z3 expression in the `value` field of `symbolic_key`, if it is
// not SymbolicAttribute. Otherwise, returns an InvalidArgumentError.
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
void AbslStringify(Sink& sink, const SymbolicAttribute& attribute) {
  absl::Format(&sink, "SymbolicAttribute{ value: '%s' }",
               attribute.value.to_string());
}

template <typename Sink>
void AbslStringify(Sink& sink, const SymbolicKey& symbolic_key) {
  std::visit(
      gutils::Overload{
          [&](const auto& variant) { absl::Format(&sink, "%v", variant); },
      },
      symbolic_key);
}

inline std::ostream& operator<<(std::ostream& os, const SymbolicKey& key) {
  return os << absl::StrCat(key);
}

// -- END OF PUBLIC INTERFACE --------------------------------------------------

using SymbolicEvalResult = std::variant<SymbolicKey, z3::expr>;

template <typename Sink>
void AbslStringify(Sink& sink, const z3::expr& expr) {
  absl::Format(&sink, "z3_expr{ '%s' }", expr.to_string());
}

template <typename Sink>
void AbslStringify(Sink& sink, const SymbolicEvalResult& result) {
  std::visit(
      gutils::Overload{
          [&](const auto& variant) { absl::Format(&sink, "%v", variant); },
      },
      result);
}

inline std::ostream& operator<<(std::ostream& os,
                                const SymbolicEvalResult& result) {
  return os << absl::StrCat(result);
}

// Exposed for testing only.
namespace internal_interpreter {

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
// NOTE: This API will only work correctly if the `solver` represents a single
// table entry (as opposed to multiple).
absl::StatusOr<SymbolicKey> AddSymbolicKey(const KeyInfo& key,
                                           z3::solver& solver);

// Creates and returns a attribute key for table priority and constrains it to
// be between 1 and MAX_INT32 (inclusive).
// NOTE: Only needed for (and should only be used with) tables that
// require/expect priority.
// NOTE: This API will only work correctly if the `solver` represents a single
// table entry (as opposed to multiple).
SymbolicAttribute AddSymbolicPriority(z3::solver& solver);

// Translates a P4-Constraints expression into a Z3 expression using the
// `environment` maps to interpret keys and attributes in the
// constraint. All symbolic keys and attributes must already exist in the
// solver's context. Invalid or not properly type-checked constraints will yield
// an InvalidArgumentError or InternalError. The `constraint_source` is used to
// construct more palatable error messages.
// NOTE: This API will only work correctly if the `solver` represents a single
// table entry (as opposed to multiple).
absl::StatusOr<z3::expr> EvaluateConstraintSymbolically(
    const ast::Expression& constraint,
    const ConstraintSource& constraint_source,
    const SymbolicEnvironment& environment, z3::solver& solver);

}  // namespace internal_interpreter

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_BACKEND_SYMBOLIC_INTERPRETER_H_
