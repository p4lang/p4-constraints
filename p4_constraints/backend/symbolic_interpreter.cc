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
#include <utility>
#include <variant>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gutils/collections.h"
#include "gutils/overload.h"
#include "gutils/source_location.h"
#include "gutils/status_builder.h"
#include "gutils/status_macros.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/backend/errors.h"
#include "p4_constraints/constraint_source.h"
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

using SymbolicEvalResultPair =
    std::variant<std::pair<z3::expr, z3::expr>,
                 std::pair<SymbolicKey, SymbolicKey>>;

absl::StatusOr<SymbolicEvalResultPair> EnsureSameType(
    const SymbolicEvalResult& expr1, const SymbolicEvalResult& expr2) {
  if (expr1.index() != expr2.index()) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "Expected expr1 and expr2 to have the same result type, but got: "
              "'"
           << expr1.index() << "' and '" << expr2.index() << "'.";
  }
  return std::visit(
      gutils::Overload{
          [&](const z3::expr& left) -> absl::StatusOr<SymbolicEvalResultPair> {
            return std::make_pair(left, std::get<z3::expr>(expr2));
          },
          [&](const SymbolicKey& left)
              -> absl::StatusOr<SymbolicEvalResultPair> {
            return std::make_pair(left, std::get<SymbolicKey>(expr2));
          },
      },
      expr1);
}

using SymbolicKeyPair =
    std::variant<std::pair<SymbolicExact, SymbolicExact>,
                 std::pair<SymbolicTernary, SymbolicTernary>,
                 std::pair<SymbolicLpm, SymbolicLpm>>;

absl::StatusOr<SymbolicKeyPair> EnsureSameType(const SymbolicKey& key1,
                                               const SymbolicKey& key2) {
  if (key1.index() != key2.index()) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "Expected key1 and key2 to have the same type, but got: "
              "'"
           << key1.index() << "' and '" << key2.index() << "'.";
  }
  return std::visit(
      gutils::Overload{
          [&](const SymbolicExact& left) -> absl::StatusOr<SymbolicKeyPair> {
            return std::make_pair(left, std::get<SymbolicExact>(key2));
          },
          [&](const SymbolicTernary& left) -> absl::StatusOr<SymbolicKeyPair> {
            return std::make_pair(left, std::get<SymbolicTernary>(key2));
          },
          [&](const SymbolicLpm& left) -> absl::StatusOr<SymbolicKeyPair> {
            return std::make_pair(left, std::get<SymbolicLpm>(key2));
          },
      },
      key1);
}

absl::Status EnsureBinopIsEqualsOrNotEquals(ast::BinaryOperator binop) {
  if (binop != ast::BinaryOperator::EQ && binop != ast::BinaryOperator::NE) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "Expected binary operation to be EQ or NE, but got: " << binop;
  }
  return absl::OkStatus();
}

// Translates a P4-Constraints binary operator on `left` and `right` to its
// equivalent Z3 constraint.
absl::StatusOr<z3::expr> EvalBinaryExpression(const z3::expr& left,
                                              ast::BinaryOperator binop,
                                              const z3::expr& right) {
  switch (binop) {
    case ast::BinaryOperator::EQ:
      return left == right;
    case ast::BinaryOperator::NE:
      return left != right;
    case ast::BinaryOperator::GT:
      return left > right;
    case ast::BinaryOperator::GE:
      return left >= right;
    case ast::BinaryOperator::LT:
      return left < right;
    case ast::BinaryOperator::LE:
      return left <= right;
    case ast::BinaryOperator::AND:
      return left && right;
    case ast::BinaryOperator::OR:
      return left || right;
    case ast::BinaryOperator::IMPLIES:
      return z3::implies(left, right);

    // Invalid values.
    default:
      break;
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << "got invalid binary operation: " << binop;
}

absl::StatusOr<z3::expr> EvalBinaryExpression(const SymbolicExact& left,
                                              ast::BinaryOperator binop,
                                              const SymbolicExact& right) {
  return EvalBinaryExpression(left.value, binop, right.value);
}

absl::StatusOr<z3::expr> EvalBinaryExpression(const SymbolicTernary& left,
                                              ast::BinaryOperator binop,
                                              const SymbolicTernary& right) {
  // Only equality (or not equality) is supported for ternaries.
  RETURN_IF_ERROR(EnsureBinopIsEqualsOrNotEquals(binop));

  ASSIGN_OR_RETURN(z3::expr value_bool,
                   EvalBinaryExpression(left.value, binop, right.value));
  ASSIGN_OR_RETURN(z3::expr mask_bool,
                   EvalBinaryExpression(left.mask, binop, right.mask));

  if (binop == ast::BinaryOperator::NE) {
    // For not equals, we use DeMorgan's law to encode !(left == right) as
    // `left.value != right.value || left.mask != right.mask`.
    return value_bool || mask_bool;
  } else {
    return value_bool && mask_bool;
  }
}

absl::StatusOr<z3::expr> EvalBinaryExpression(const SymbolicLpm& left,
                                              ast::BinaryOperator binop,
                                              const SymbolicLpm& right) {
  // Only equality (or not equality) is supported for LPMs.
  RETURN_IF_ERROR(EnsureBinopIsEqualsOrNotEquals(binop));

  ASSIGN_OR_RETURN(z3::expr value_bool,
                   EvalBinaryExpression(left.value, binop, right.value));
  ASSIGN_OR_RETURN(
      z3::expr prefix_length_bool,
      EvalBinaryExpression(left.prefix_length, binop, right.prefix_length));

  if (binop == ast::BinaryOperator::NE) {
    // For not equals, we use DeMorgan's law to encode !(left == right) as
    // `left.value != right.value || left.prefix_length != right.prefix_length`.
    return value_bool || prefix_length_bool;
  } else {
    return value_bool && prefix_length_bool;
  }
}

absl::StatusOr<z3::expr> EvalBinaryExpression(const SymbolicKey& left,
                                              ast::BinaryOperator binop,
                                              const SymbolicKey& right) {
  // The left and the right key must have the same type.
  ASSIGN_OR_RETURN(SymbolicKeyPair left_right_pair, EnsureSameType(left, right),
                   _ << " for left key:\n"
                     << left << "\nAnd right key:\n"
                     << right);
  return std::visit(
      [&](const auto& pair) {
        return EvalBinaryExpression(pair.first, binop, pair.second);
      },
      left_right_pair);
}

absl::StatusOr<z3::expr> EvalBinaryExpression(const SymbolicEvalResult& left,
                                              ast::BinaryOperator binop,
                                              const SymbolicEvalResult& right) {
  // The left and the right key must have the same type.
  ASSIGN_OR_RETURN(SymbolicEvalResultPair left_right_pair,
                   EnsureSameType(left, right),
                   _ << " for left result:\n"
                     << left << "\nAnd right result:\n"
                     << right);
  return std::visit(
      [&](const auto& pair) {
        return EvalBinaryExpression(pair.first, binop, pair.second);
      },
      left_right_pair);
}

absl::StatusOr<SymbolicEvalResult> EvalTypeCast(
    const z3::expr& expr_to_cast, const ast::Type& type_to_cast_to,
    z3::solver& solver) {
  ASSIGN_OR_RETURN(
      int bitwidth, ast::TypeBitwidthOrStatus(type_to_cast_to),
      _ << "expressions can only be cast to types with bitwidths, but "
           "got: "
        << type_to_cast_to);

  // Only a small set of type casts are allowed. See the `ast.proto` or
  // `type_checker.cc` for details.
  switch (type_to_cast_to.type_case()) {
    case ast::Type::kFixedUnsigned:
      // We must be typecasting int ~~> bit<W>.
      return z3::int2bv(bitwidth, expr_to_cast);
    case ast::Type::kExact:
      // We must be typecasting bit<W> ~~> Exact<W>
      return SymbolicExact{
          .value = expr_to_cast,
      };
    case ast::Type::kOptionalMatch:
    case ast::Type::kTernary:
      // We must be typecasting bit<W> ~~> Ternary<W>
      return SymbolicTernary{
          .value = expr_to_cast,
          // '-1' is equivalent to an all_ones bitvector in Z3.
          .mask = solver.ctx().bv_val(-1, bitwidth),
      };
    case ast::Type::kLpm:
      // We must be typecasting bit<W> ~~> Lpm<W>
      return SymbolicLpm{
          .value = expr_to_cast,
          .prefix_length = solver.ctx().int_val(bitwidth),
      };

    // TODO(b/291779521): Range matches are not currently supported.
    case ast::Type::kRange:
      return gutils::UnimplementedErrorBuilder(GUTILS_LOC)
             << "Range matches are not currently supported by the "
                "p4-constraints symbolic representation.";

    case ast::Type::kUnknown:
    case ast::Type::kUnsupported:
    case ast::Type::kBoolean:
    case ast::Type::kArbitraryInt:
    case ast::Type::TYPE_NOT_SET:
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "cannot cast expression to type " << type_to_cast_to;
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << "Got invalid type to cast to: " << type_to_cast_to;
}

// Forward declared to allow mutual-recursion.
absl::StatusOr<SymbolicEvalResult> EvalSymbolically(
    const ast::Expression& expr, const ConstraintSource& constraint_source,
    const absl::flat_hash_map<std::string, SymbolicKey>& symbolic_key_by_name,
    const absl::flat_hash_map<std::string, SymbolicAttribute>&
        symbolic_attribute_by_name,
    z3::solver& solver);

template <class T>
absl::StatusOr<T> EvalSymbolicallyTo(
    const ast::Expression& expr, const ConstraintSource& constraint_source,
    const absl::flat_hash_map<std::string, SymbolicKey>& symbolic_key_by_name,
    const absl::flat_hash_map<std::string, SymbolicAttribute>&
        symbolic_attribute_by_name,
    z3::solver& solver) {
  ASSIGN_OR_RETURN(
      SymbolicEvalResult result,
      EvalSymbolically(expr, constraint_source, symbolic_key_by_name,
                       symbolic_attribute_by_name, solver));

  T* t = std::get_if<T>(&result);
  if (t == nullptr) {
    return RuntimeTypeError(constraint_source, expr.start_location(),
                            expr.end_location())
           << "Expected an expression that evaluates to a '" << typeid(T).name()
           << "', but got: " << result << " for expression:\n"
           << expr.DebugString();
  }
  return std::move(*t);
}

absl::StatusOr<SymbolicEvalResult> EvalSymbolically(
    const ast::Expression& expr, const ConstraintSource& constraint_source,
    const absl::flat_hash_map<std::string, SymbolicKey>& symbolic_key_by_name,
    const absl::flat_hash_map<std::string, SymbolicAttribute>&
        symbolic_attribute_by_name,
    z3::solver& solver) {
  switch (expr.expression_case()) {
    case ast::Expression::kBooleanConstant:
      return solver.ctx().bool_val(expr.boolean_constant());

    case ast::Expression::kBooleanNegation: {
      ASSIGN_OR_RETURN(
          z3::expr bool_result,
          EvalSymbolicallyTo<z3::expr>(expr.boolean_negation(),
                                       constraint_source, symbolic_key_by_name,
                                       symbolic_attribute_by_name, solver));
      return !bool_result;
    }

    case ast::Expression::kIntegerConstant:
      return solver.ctx().int_val(expr.integer_constant().c_str());

    case ast::Expression::kArithmeticNegation: {
      ASSIGN_OR_RETURN(
          z3::expr int_result,
          EvalSymbolicallyTo<z3::expr>(expr.arithmetic_negation(),
                                       constraint_source, symbolic_key_by_name,
                                       symbolic_attribute_by_name, solver));
      return -int_result;
    }

    case ast::Expression::kKey: {
      ASSIGN_OR_RETURN(
          const SymbolicKey* key,
          gutils::FindPtrOrStatus(symbolic_key_by_name, expr.key()));
      return *key;
    }

    case ast::Expression::kFieldAccess: {
      // There are no nested field accesses supported in P4-Constraints at the
      // moment. If there were, this logic would need to change.
      ASSIGN_OR_RETURN(
          const SymbolicKey* key,
          gutils::FindPtrOrStatus(symbolic_key_by_name,
                                  expr.field_access().expr().key()));
      return GetFieldAccess(*key, expr.field_access().field());
    }

    case ast::Expression::kAttributeAccess: {
      // All attributes should be in the map.
      ASSIGN_OR_RETURN(
          const SymbolicAttribute* attribute,
          gutils::FindPtrOrStatus(symbolic_attribute_by_name,
                                  expr.attribute_access().attribute_name()));
      return attribute->value;
    }

    case ast::Expression::kBinaryExpression: {
      ASSIGN_OR_RETURN(SymbolicEvalResult left_result,
                       EvalSymbolically(expr.binary_expression().left(),
                                        constraint_source, symbolic_key_by_name,
                                        symbolic_attribute_by_name, solver));
      ASSIGN_OR_RETURN(SymbolicEvalResult right_result,
                       EvalSymbolically(expr.binary_expression().right(),
                                        constraint_source, symbolic_key_by_name,
                                        symbolic_attribute_by_name, solver));
      return EvalBinaryExpression(left_result, expr.binary_expression().binop(),
                                  right_result);
    }

    case ast::Expression::kTypeCast: {
      ASSIGN_OR_RETURN(
          z3::expr pre_type_cast_result,
          EvalSymbolicallyTo<z3::expr>(expr.type_cast(), constraint_source,
                                       symbolic_key_by_name,
                                       symbolic_attribute_by_name, solver));
      return EvalTypeCast(pre_type_cast_result, expr.type(), solver);
    }

    case ast::Expression::EXPRESSION_NOT_SET:
      break;
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << "got invalid expression: " << expr.DebugString();
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

absl::StatusOr<z3::expr> EvaluateConstraintSymbolically(
    const ast::Expression& constraint,
    const ConstraintSource& constraint_source,
    const absl::flat_hash_map<std::string, SymbolicKey>& symbolic_key_by_name,
    const absl::flat_hash_map<std::string, SymbolicAttribute>&
        symbolic_attribute_by_name,
    z3::solver& solver) {
  // TODO(b/296865478): Run the typechecker here instead when it is idempotent.
  if (!constraint.type().has_boolean()) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "expected a constraint of type boolean, but got:\n"
           << constraint.DebugString();
  }
  return EvalSymbolicallyTo<z3::expr>(constraint, constraint_source,
                                      symbolic_key_by_name,
                                      symbolic_attribute_by_name, solver);
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
