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

#include "p4_constraints/backend/symbolic_interpreter.h"

#include <cstdint>
#include <limits>
#include <string>
#include <variant>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gutils/overload.h"
#include "gutils/source_location.h"
#include "gutils/status_builder.h"
#include "gutils/status_macros.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "z3++.h"

namespace p4_constraints {
namespace {

absl::StatusOr<z3::expr> GetFieldAccess(const SymbolicKey& symbolic_key,
                                        absl::string_view field) {
  return std::visit(
      gutils::Overload{
          [&](const SymbolicExact& exact) -> absl::StatusOr<z3::expr> {
            if (field == "value") return exact.value;
            return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
                   << "Exact has no field '" << field << "'";
          },
          [&](const SymbolicTernary& ternary) -> absl::StatusOr<z3::expr> {
            if (field == "value") return ternary.value;
            if (field == "mask") return ternary.mask;
            return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
                   << "Ternary has no field \"" << field << "\"";
          },
          [&](const SymbolicLpm& lpm) -> absl::StatusOr<z3::expr> {
            if (field == "value") return lpm.value;
            if (field == "prefix_length") return lpm.prefix_length;
            return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
                   << "LPM has no field \"" << field << "\"";
          },
      },
      symbolic_key);
}

}  // namespace

absl::StatusOr<SymbolicKey> AddSymbolicKey(const KeyInfo& key,
                                           z3::solver& solver) {
  ASSIGN_OR_RETURN(int bitwidth, ast::TypeBitwidthOrStatus(key.type));
  if (bitwidth == 0) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "expected a key type with bitwidth > 0, but got: " << key;
  }
  switch (key.type.type_case()) {
    case ast::Type::kExact: {
      return SymbolicExact{
          .value = solver.ctx().bv_const(key.name.c_str(), bitwidth),
      };
    }
    case ast::Type::kOptionalMatch:
    case ast::Type::kTernary: {
      // Optionals and ternaries are both encoded as ternaries.
      z3::expr value = solver.ctx().bv_const(key.name.c_str(), bitwidth);
      z3::expr mask = solver.ctx().bv_const(
          absl::StrCat(key.name, "_mask").c_str(), bitwidth);
      // This is a P4RT canonicity constraint ensuring that masked-off bits must
      // be zero.
      solver.add((mask & value) == value);
      if (key.type.has_optional_match()) {
        // For optionals in P4RT, the mask must be either 0 (denoting a
        // wildcard) or all ones (denoting an exact match). '-1' is equivalent
        // to an all_one bitvector in Z3.
        solver.add(mask == 0 || mask == -1);
      }
      return SymbolicTernary{
          .value = value,
          .mask = mask,
      };
    }
    case ast::Type::kLpm: {
      z3::expr value = solver.ctx().bv_const(key.name.c_str(), bitwidth);
      z3::expr prefix_length = solver.ctx().int_const(
          absl::StrCat(key.name, "_prefix_length").c_str());
      z3::expr suffix_length = z3::int2bv(
          /*bitwidth=*/bitwidth, /*z3_int_expr=*/bitwidth - prefix_length);
      // For LPMs, the prefix length must be no larger than the bitwidth, and
      // only `prefix_length` bits of the value should be set. We capture the
      // second constraint by saying that the value is unchanged after two bit
      // shifts.
      solver.add(prefix_length >= 0 && prefix_length <= bitwidth &&
                 z3::shl(z3::lshr(value, suffix_length), suffix_length) ==
                     value);
      return SymbolicLpm{
          .value = value,
          .prefix_length = prefix_length,
      };
    }

    // TODO(b/291779521): Range matches are not currently supported.
    case ast::Type::kRange:
      return gutils::UnimplementedErrorBuilder(GUTILS_LOC)
             << "Range matches are not currently supported by the "
                "p4-constraints symbolic representation.";

    // Non-match types.
    case ast::Type::kUnknown:
    case ast::Type::kUnsupported:
    case ast::Type::kBoolean:
    case ast::Type::kArbitraryInt:
    case ast::Type::kFixedUnsigned:
    case ast::Type::TYPE_NOT_SET:
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "expected a match type, but got: " << key;
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << "got invalid type: " << key;
}

SymbolicAttribute AddSymbolicPriority(z3::solver& solver) {
  z3::expr priority_key = solver.ctx().int_const("priority");
  solver.add(priority_key > 0);
  solver.add(priority_key <= std::numeric_limits<int32_t>::max());
  return SymbolicAttribute{.value = priority_key};
}

absl::StatusOr<z3::expr> GetValue(const SymbolicKey& symbolic_key) {
  return GetFieldAccess(symbolic_key, "value");
}

absl::StatusOr<z3::expr> GetMask(const SymbolicKey& symbolic_key) {
  return GetFieldAccess(symbolic_key, "mask");
}

absl::StatusOr<z3::expr> GetPrefixLength(const SymbolicKey& symbolic_key) {
  return GetFieldAccess(symbolic_key, "prefix_length");
}

}  // namespace p4_constraints
