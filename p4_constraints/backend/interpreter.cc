// Copyright 2020 The P4-Constraints Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "p4_constraints/backend/interpreter.h"

#include <gmp.h>
#include <gmpxx.h>
#include <stddef.h>

#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "glog/logging.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/quote.h"
#include "p4/v1/p4runtime.pb.h"
#include "util/integral_types.h"
#include "util/status.h"
#include "util/ret_check.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace p4_constraints {

using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::Type;

namespace internal_interpreter {

// -> Key data structures defined in header file.

// -- Pretty printing ----------------------------------------------------------

// Returns P4Info object ID as string, both including and excluding its object
// type, which is encoded in the 8 most significant bits of the ID.
// See P4Runtime specification, "6.3 ID Allocation for P4Info Objects".
std::string P4IDToString(uint32 p4_object_id) {
  // Erase 8 most significant bits, which determine the P4Info object type.
  uint32 id_without_type_prefix = p4_object_id & 0x00ffffff;
  if (id_without_type_prefix == p4_object_id) {
    // When no type prefix is included for whatever reason, simply return ID.
    return absl::StrFormat("%d (0x%.8x)", p4_object_id, p4_object_id);
  }
  return absl::StrFormat("%d (full ID: %d (0x%.8x))", id_without_type_prefix,
                         p4_object_id, p4_object_id);
}

// -- Parsing P4RT table entries -----------------------------------------------

// See https://p4.org/p4runtime/spec/master/P4Runtime-Spec.html#sec-bytestrings.
util::StatusOr<Integer> ParseP4RTInteger(const std::string& int_str) {
  mpz_class integer;
  const char* chars = int_str.c_str();
  const size_t char_count = strlen(chars);
  constexpr int most_significant_first = 1;
  constexpr size_t char_size = sizeof(char);
  static_assert(char_size == 1, "expected sizeof(char) == 1");
  constexpr int endian = 0;    // system default
  constexpr size_t nails = 0;  // don't skip any bits
  mpz_import(integer.get_mpz_t(), char_count, most_significant_first, char_size,
             endian, nails, chars);
  return integer;
}

// Returns (table key name, table key value)-pair.
util::StatusOr<std::pair<std::string, EvalResult>> ParseKey(
    const p4::v1::FieldMatch& p4field, const TableInfo& table_info) {
  auto it = table_info.keys_by_id.find(p4field.field_id());
  if (it == table_info.keys_by_id.end()) {
    return util::InvalidArgumentErrorBuilder(UTIL_LOC)
           << "unknown table key with ID " << P4IDToString(p4field.field_id());
  }
  const KeyInfo& key = it->second;

  switch (p4field.field_match_type_case()) {
    case p4::v1::FieldMatch::kExact: {
      RET_CHECK_EQ(key.type.type_case(), Type::kExact)
          << "P4RT table entry inconsistent with P4 program";
      ASSIGN_OR_RETURN(Integer value, ParseP4RTInteger(p4field.exact().value()),
                       _ << " while parsing exact key " << key.name);
      return {std::make_pair(key.name, Exact{.value = value})};
    }

    case p4::v1::FieldMatch::kTernary: {
      RET_CHECK_EQ(key.type.type_case(), Type::kTernary)
          << "P4RT table entry inconsistent with P4 program";
      ASSIGN_OR_RETURN(Integer value,
                       ParseP4RTInteger(p4field.ternary().value()),
                       _ << " while parsing value of ternary key " << key.name);
      ASSIGN_OR_RETURN(Integer mask, ParseP4RTInteger(p4field.ternary().mask()),
                       _ << " while parsing mask of ternary key " << key.name);
      return {std::make_pair(key.name, Ternary{.value = value, .mask = mask})};
    }

    case p4::v1::FieldMatch::kLpm: {
      RET_CHECK_EQ(key.type.type_case(), Type::kLpm)
          << "P4RT table entry inconsistent with P4 program";
      ASSIGN_OR_RETURN(Integer value, ParseP4RTInteger(p4field.lpm().value()),
                       _ << " while parsing value of LPM key " << key.name);
      Integer prefix_len = mpz_class(p4field.lpm().prefix_len());
      return {std::make_pair(key.name,
                             Lpm{.value = value, .prefix_length = prefix_len})};
    }

    case p4::v1::FieldMatch::kRange: {
      RET_CHECK_EQ(key.type.type_case(), Type::kRange)
          << "P4RT table entry inconsistent with P4 program";
      ASSIGN_OR_RETURN(
          Integer low, ParseP4RTInteger(p4field.range().low()),
          _ << " while parsing field 'low' of range key " << key.name);
      ASSIGN_OR_RETURN(
          Integer high, ParseP4RTInteger(p4field.range().high()),
          _ << " while parsing field 'high' of range key " << key.name);
      return {std::make_pair(key.name, Range{.low = low, .high = high})};
    }

    default:
      return util::InvalidArgumentErrorBuilder(UTIL_LOC)
             << "unsupported P4RT field match type "
             << p4field.field_match_type_case();
  }
}

util::StatusOr<TableEntry> ParseEntry(const p4::v1::TableEntry& entry,
                                      const TableInfo& table_info) {
  absl::flat_hash_map<std::string, EvalResult> keys;
  for (const p4::v1::FieldMatch& field : entry.match()) {
    ASSIGN_OR_RETURN(auto kv, ParseKey(field, table_info),
                     _ << " while parsing P4RT table entry");
    auto result = keys.insert(kv);
    if (result.second == false) {
      return util::InvalidArgumentErrorBuilder(UTIL_LOC)
             << "Unable to parse P4RT table entry: duplicate match on key "
             << kv.first << " with ID " << P4IDToString(field.field_id());
    }
  }
  return TableEntry{.table_name = table_info.name, .keys = keys};
}

// -- Error handling -----------------------------------------------------------

util::StatusBuilder TypeError(const ast::SourceLocation& start,
                              const ast::SourceLocation& end) {
  return util::InternalErrorBuilder(UTIL_LOC)
         << QuoteSourceLocation(start, end) << "Runtime type error: ";
}

// -- Auxiliary evaluators -----------------------------------------------------

// Like Eval, but ensuring the result is a bool.
util::StatusOr<bool> EvalToBool(const Expression& expr,
                                const TableEntry& entry) {
  ASSIGN_OR_RETURN(EvalResult result, Eval(expr, entry));
  if (absl::holds_alternative<bool>(result)) return absl::get<bool>(result);
  return TypeError(expr.start_location(), expr.end_location())
         << "expected expression of type bool";
}

// Like Eval, but ensuring the result is an Integer.
util::StatusOr<Integer> EvalToInt(const Expression& expr,
                                  const TableEntry& entry) {
  ASSIGN_OR_RETURN(EvalResult result, Eval(expr, entry));
  if (absl::holds_alternative<Integer>(result))
    return absl::get<Integer>(result);
  return TypeError(expr.start_location(), expr.end_location())
         << "expected expression of integral type";
}

util::StatusOr<EvalResult> EvalAndCastTo(const Type& type,
                                         const Expression& expr,
                                         const TableEntry& entry) {
  ASSIGN_OR_RETURN(EvalResult result, Eval(expr, entry));
  if (!absl::holds_alternative<Integer>(result))
    return TypeError(expr.start_location(), expr.end_location())
           << "expected expression of (or castable to) type " << type;
  const Integer value = absl::get<Integer>(result);
  const Integer one = mpz_class(1);
  const Integer zero = mpz_class(0);
  const int bitwidth = TypeBitwidth(type).value_or(-1);
  DCHECK_NE(bitwidth, -1) << "can only cast to fixed-size types";
  switch (type.type_case()) {
    // int ~~> bit<W>
    //   n |~> n mod 2^W
    case Type::kFixedUnsigned: {
      Integer domain_size = one << bitwidth;  // 2^W
      Integer fixed_value = value % domain_size;
      // operator% may return negative values.
      return {fixed_value >= zero ? 
                fixed_value : 
                (fixed_value + domain_size)};
    }

    // bit<W> ~~> Exact<W>
    //      n |~> Exact { value = n }
    case Type::kExact:
      return {Exact{.value = value}};

    // bit<W> ~~> Ternary<W>
    //      n |~> Ternary { value = n; mask = 2^W-1 }
    case Type::kTernary: {
      Integer mask = (one << bitwidth) - one;  // 2^W - 1
      return {Ternary{.value = value, .mask = mask}};
    }

    // bit<W> ~~> LPM<W>
    //      n |~> LPM { value = n; prefix_length = W }
    case Type::kLpm:
      return {Lpm{.value = value, .prefix_length = mpz_class(bitwidth)}};

    // bit<W> ~~> Range<W>
    //      n |~> Range { low = n; high = n }
    case Type::kRange:
      return {Range{.low = value, .high = value}};

    default:
      return util::InternalErrorBuilder(UTIL_LOC)
             << "don't know how to cast to type " << type;
  }
}

util::StatusOr<bool> EvalBinaryExpression(ast::BinaryOperator binop,
                                          const Expression& left_expr,
                                          const Expression& right_expr,
                                          const TableEntry& entry) {
  switch (binop) {
    // (In-)Equality comparison.
    case ast::EQ:
    case ast::NE: {
      ASSIGN_OR_RETURN(EvalResult left, Eval(left_expr, entry));
      ASSIGN_OR_RETURN(EvalResult right, Eval(right_expr, entry));
      // Avoid != so we don't have to define it for Exact/Ternary/Lpm/Range.
      return (binop == ast::EQ) ? (left == right) : !(left == right);
    }

    // Ordered comparison.
    case ast::GT:
    case ast::GE:
    case ast::LT:
    case ast::LE: {
      // Ordered comparison (<, <=, >, >=) is only supported by types whose run-
      // time representation is Integer; the type checker should have our back.
      ASSIGN_OR_RETURN(Integer left, EvalToInt(left_expr, entry),
                       _ << " in ordered comparison");
      ASSIGN_OR_RETURN(Integer right, EvalToInt(right_expr, entry),
                       _ << " in ordered comparison");
      switch (binop) {
        case ast::GT:
          return left > right;
        case ast::GE:
          return left >= right;
        case ast::LT:
          return left < right;
        case ast::LE:
          return left <= right;
        default:
          [[fallthrough]];
      }
    }

    // Boolean operations. List explicitly to avoid confusing type errors.
    case ast::AND:
    case ast::OR:
    case ast::IMPLIES: {
      // Short circuit boolean operations.
      ASSIGN_OR_RETURN(bool left_true, EvalToBool(left_expr, entry));
      switch (binop) {
        case ast::AND:
          if (left_true)
            return EvalToBool(right_expr, entry);
          else
            return false;
        case ast::OR:
          if (left_true)
            return true;
          else
            return EvalToBool(right_expr, entry);
        case ast::IMPLIES:
          if (left_true)
            return EvalToBool(right_expr, entry);
          else
            return true;
        default:
          [[fallthrough]];
      }
    }

    default:
      return util::InternalErrorBuilder(UTIL_LOC)
             << "unknown binary operator " << ast::BinaryOperator_Name(binop)
             << " encountered at runtime";
  }
}

struct EvalFieldAccess {
  const absl::string_view field;

  util::Status Error(const std::string& type) {
    return util::InvalidArgumentErrorBuilder(UTIL_LOC)
           << "value of type " << type << " has no field " << field;
  }

  util::StatusOr<EvalResult> operator()(const Exact& exact) {
    if (field == "value") return {exact.value};
    return Error("exact");
  }

  util::StatusOr<EvalResult> operator()(const Ternary& ternary) {
    if (field == "value") return {ternary.value};
    if (field == "mask") return {ternary.mask};
    return Error("ternary");
  }

  util::StatusOr<EvalResult> operator()(const Lpm& lpm) {
    if (field == "value") return {lpm.value};
    if (field == "prefix_length") return {lpm.prefix_length};
    return Error("lpm");
  }

  util::StatusOr<EvalResult> operator()(const Range& range) {
    if (field == "low") return {range.low};
    if (field == "high") return {range.high};
    return Error("range");
  }

  util::StatusOr<EvalResult> operator()(bool b) { return Error("bool"); }

  util::StatusOr<EvalResult> operator()(const Integer& i) {
    return Error("int");
  }
};

// -- Main evaluator -----------------------------------------------------------

// Evaluates Expression over given table entry, returning EvalResult if
// successful or InternalError Status if a type mismatch is detected.
//
// Eval (without underscore) is a thin wrapper around Eval_, see further down;
// Eval_ should never be called directly, except by Eval.
util::StatusOr<EvalResult> Eval_(const Expression& expr,
                                 const TableEntry& entry) {
  switch (expr.expression_case()) {
    case Expression::kBooleanConstant:
      return {expr.boolean_constant()};

    case Expression::kIntegerConstant: {
      mpz_class result;
      if (result.set_str(expr.integer_constant(), 10) == 0) return {result};
      return util::InternalErrorBuilder(UTIL_LOC)
             << "AST invariant violated; invalid decimal string: "
             << expr.integer_constant();
    }

    case Expression::kKey: {
      auto it = entry.keys.find(expr.key());
      if (it == entry.keys.end())
        TypeError(expr.start_location(), expr.end_location())
            << "unknown key " << expr.key() << " in table " << entry.table_name;
      return it->second;
    }

    case Expression::kBooleanNegation: {
      ASSIGN_OR_RETURN(bool result, EvalToBool(expr.boolean_negation(), entry));
      return {!result};
    }

    case Expression::kArithmeticNegation: {
      ASSIGN_OR_RETURN(Integer result,
                       EvalToInt(expr.arithmetic_negation(), entry));
      return {-result};
    }

    case Expression::kTypeCast: {
      return EvalAndCastTo(expr.type(), expr.type_cast(), entry);
    }

    case Expression::kBinaryExpression: {
      const ast::BinaryExpression& binexpr = expr.binary_expression();
      return EvalBinaryExpression(binexpr.binop(), binexpr.left(),
                                  binexpr.right(), entry);
    }

    case Expression::kFieldAccess: {
      const Expression& composite_expr = expr.field_access().expr();
      const std::string& field = expr.field_access().field();
      ASSIGN_OR_RETURN(EvalResult composite_value, Eval(composite_expr, entry));
      util::StatusOr<EvalResult> result =
          absl::visit(EvalFieldAccess{.field = field}, composite_value);
      if (!result.ok()) {
        return TypeError(expr.start_location(), expr.end_location())
               << result.status().message();
      }
      return result;
    }

    case Expression::EXPRESSION_NOT_SET:
      return util::InvalidArgumentErrorBuilder(UTIL_LOC)
             << "invalid expression: " << expr.DebugString();

    default:
      return util::UnimplementedErrorBuilder(UTIL_LOC)
             << "unknown expression case: " << expr.expression_case();
  }
}

// -- Sanity checking ----------------------------------------------------------

// We wrap Eval_ with a cautionary dynamic type check to ease debugging.

util::Status DynamicTypeCheck(const Expression& expr, const EvalResult result) {
  switch (expr.type().type_case()) {
    case Type::kBoolean:
      if (absl::holds_alternative<bool>(result)) return {};
      break;
    case Type::kArbitraryInt:
    case Type::kFixedUnsigned:
      if (absl::holds_alternative<Integer>(result)) return {};
      break;
    case Type::kExact:
      if (absl::holds_alternative<Exact>(result)) return {};
      break;
    case Type::kTernary:
      if (absl::holds_alternative<Ternary>(result)) return {};
      break;
    case Type::kLpm:
      if (absl::holds_alternative<Lpm>(result)) return {};
      break;
    case Type::kRange:
      if (absl::holds_alternative<Range>(result)) return {};
      break;
    default:
      break;
  }
  return TypeError(expr.start_location(), expr.end_location())
         << "unexpected runtime representation of type " << expr.type();
}

// Wraps Eval_ with dynamic type check to ease debugging. Never call Eval_
// directly; call Eval instead.
util::StatusOr<EvalResult> Eval(const Expression& expr,
                                const TableEntry& entry) {
  ASSIGN_OR_RETURN(EvalResult result, Eval_(expr, entry));
  RETURN_IF_ERROR(DynamicTypeCheck(expr, result));
  return result;
}

}  // namespace internal_interpreter

// -- Public interface ---------------------------------------------------------

util::StatusOr<bool> EntryMeetsConstraint(const p4::v1::TableEntry& entry,
                                          const ConstraintInfo& context) {
  using ::p4_constraints::internal_interpreter::EvalToBool;
  using ::p4_constraints::internal_interpreter::P4IDToString;
  using ::p4_constraints::internal_interpreter::ParseEntry;
  using ::p4_constraints::internal_interpreter::TableEntry;

  // Find table associated with entry and parse the entry.
  auto it = context.find(entry.table_id());
  if (it == context.end())
    return util::InvalidArgumentErrorBuilder(UTIL_LOC)
           << "table entry with unknown table ID "
           << P4IDToString(entry.table_id());
  const TableInfo& table_info = it->second;
  ASSIGN_OR_RETURN(TableEntry parsed_entry, ParseEntry(entry, table_info));

  // Check if entry satisfies table constraint (if present).
  if (!table_info.constraint.has_value()) {
    VLOG(1) << "Table \"" << table_info.name
            << "\" has no constraint; accepting entry unconditionally.";
    return true;
  }
  const Expression& constraint = table_info.constraint.value();
  if (constraint.type().type_case() != Type::kBoolean) {
    return util::InvalidArgumentErrorBuilder(UTIL_LOC)
           << "table " << table_info.name
           << " has non-boolean constraint: " << constraint.DebugString();
  }
  return EvalToBool(constraint, parsed_entry);
}

}  // namespace p4_constraints
