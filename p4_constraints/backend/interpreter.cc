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
#include <string>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "glog/logging.h"
#include "gutils/ret_check.h"
#include "gutils/status_macros.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/quote.h"

namespace p4_constraints {

using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::Type;

namespace internal_interpreter {

// -> Key data structures defined in header file.

// -- Pretty printing ----------------------------------------------------------

// Returns P4Info object ID as string, both including and excluding its object
// type, which is encoded in the 8 most significant bits of the ID.
// See P4Runtime specification, "6.3 ID Allocation for P4Info Objects".
std::string P4IDToString(uint32_t p4_object_id) {
  // Erase 8 most significant bits, which determine the P4Info object type.
  uint32_t id_without_type_prefix = p4_object_id & 0x00ffffff;
  if (id_without_type_prefix == p4_object_id) {
    // When no type prefix is included for whatever reason, simply return ID.
    return absl::StrFormat("%d (0x%.8x)", p4_object_id, p4_object_id);
  }
  return absl::StrFormat("%d (full ID: %d (0x%.8x))", id_without_type_prefix,
                         p4_object_id, p4_object_id);
}

// -- Parsing P4RT table entries -----------------------------------------------

// See https://p4.org/p4runtime/spec/master/P4Runtime-Spec.html#sec-bytestrings.
static absl::StatusOr<Integer> ParseP4RTInteger(const std::string& int_str) {
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

static Integer MaxValueForBitwidth(int bitwidth) {
  // 2^bitwidth - 1
  return (mpz_class(1) << bitwidth) - mpz_class(1);
}

// Returns (table key name, table key value)-pair.
absl::StatusOr<std::pair<std::string, EvalResult>> ParseKey(
    const p4::v1::FieldMatch& p4field, const TableInfo& table_info) {
  auto it = table_info.keys_by_id.find(p4field.field_id());
  if (it == table_info.keys_by_id.end()) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
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

    case p4::v1::FieldMatch::kOptional: {
      RET_CHECK_EQ(key.type.type_case(), Type::kOptionalMatch)
          << "P4RT table entry inconsistent with P4 program";
      ASSIGN_OR_RETURN(
          Integer value, ParseP4RTInteger(p4field.optional().value()),
          _ << " while parsing field 'value' of optional key " << key.name);
      return {std::make_pair(
          key.name, Ternary{.value = value,
                            .mask = MaxValueForBitwidth(
                                key.type.optional_match().bitwidth())})};
    }

    default:
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "unsupported P4RT field match type "
             << p4field.field_match_type_case();
  }
}

absl::StatusOr<TableEntry> ParseEntry(const p4::v1::TableEntry& entry,
                                      const TableInfo& table_info) {
  absl::flat_hash_map<std::string, EvalResult> keys;

  // Parse all keys that are explicitly present.
  for (const p4::v1::FieldMatch& field : entry.match()) {
    ASSIGN_OR_RETURN(auto kv, ParseKey(field, table_info));
    auto result = keys.insert(kv);
    if (result.second == false) {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "duplicate match on key " << kv.first << " with ID "
             << P4IDToString(field.field_id());
    }
  }

  // Use default value for omitted keys.
  // See Section 9.1.1. of the P4runtime specification.
  for (const auto& [name, key_info] : table_info.keys_by_name) {
    if (keys.contains(name)) continue;
    switch (key_info.type.type_case()) {
      case ast::Type::kExact:
        return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
               << "missing exact match key '" << key_info.name << "'";
      case ast::Type::kTernary:
      case ast::Type::kOptionalMatch:
        keys[name] = Ternary{};
        continue;
      case ast::Type::kLpm:
        keys[name] = Lpm{};
        continue;
      case ast::Type::kRange:
        keys[name] = Range{
            .low = mpz_class(0),
            .high = MaxValueForBitwidth(key_info.type.range().bitwidth()),
        };
        continue;
      case ast::Type::kBoolean:
      case ast::Type::kArbitraryInt:
      case ast::Type::kFixedUnsigned:
      case ast::Type::kUnknown:
      case ast::Type::kUnsupported:
      case ast::Type::TYPE_NOT_SET:
        break;
    }
    return gutils::InternalErrorBuilder(GUTILS_LOC)
           << "Key '" << key_info.name
           << "' of invalid match type detected at runtime: "
           << key_info.type.DebugString();
  }

  return TableEntry{
      .table_name = table_info.name,
      .priority = entry.priority(),
      .keys = keys,
  };
}

// -- Error handling -----------------------------------------------------------

gutils::StatusBuilder TypeError(const ast::SourceLocation& start,
                                const ast::SourceLocation& end) {
  return gutils::InternalErrorBuilder(GUTILS_LOC)
         << QuoteSourceLocation(start, end) << "Runtime type error: ";
}

// -- Auxiliary evaluators -----------------------------------------------------

// Like Eval, but ensuring the result is a bool. Caches Boolean results and
// checks cache before evaluation to avoid recomputation.
absl::StatusOr<bool> EvalToBool(const Expression& expr, const TableEntry& entry,
                                EvaluationCache* eval_cache) {
  if (eval_cache != nullptr) {
    auto cache_result = eval_cache->find(&expr);
    if (cache_result != eval_cache->end()) return cache_result->second;
  }
  ASSIGN_OR_RETURN(EvalResult result, Eval(expr, entry, eval_cache));
  if (absl::holds_alternative<bool>(result)) {
    if (eval_cache != nullptr)
      eval_cache->insert({&expr, absl::get<bool>(result)});
    return absl::get<bool>(result);
  } else {
    return TypeError(expr.start_location(), expr.end_location())
           << "expected expression of type bool";
  }
}

// Like Eval, but ensuring the result is an Integer.
absl::StatusOr<Integer> EvalToInt(const Expression& expr,
                                  const TableEntry& entry,
                                  EvaluationCache* eval_cache) {
  ASSIGN_OR_RETURN(EvalResult result, Eval(expr, entry, eval_cache));
  if (absl::holds_alternative<Integer>(result))
    return absl::get<Integer>(result);
  return TypeError(expr.start_location(), expr.end_location())
         << "expected expression of integral type";
}

absl::StatusOr<EvalResult> EvalAndCastTo(const Type& type,
                                         const Expression& expr,
                                         const TableEntry& entry,
                                         EvaluationCache* eval_cache) {
  ASSIGN_OR_RETURN(EvalResult result, Eval(expr, entry, eval_cache));
  if (absl::holds_alternative<Integer>(result)) {
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
        if (fixed_value < zero) fixed_value += domain_size;
        return {fixed_value};
      }

      // bit<W> ~~> Exact<W>
      //      n |~> Exact { value = n }
      case Type::kExact:
        return {Exact{.value = value}};

      // bit<W> ~~> Ternary<W>/Optional<W>
      //      n |~> Ternary { value = n; mask = 2^W-1 }
      case Type::kTernary:
      case Type::kOptionalMatch: {
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
        break;
    }
  }
  return TypeError(expr.start_location(), expr.end_location())
         << "cannot cast expression of type " << expr.type() << " to type "
         << type;
}

absl::StatusOr<bool> EvalBinaryExpression(ast::BinaryOperator binop,
                                          const Expression& left_expr,
                                          const Expression& right_expr,
                                          const TableEntry& entry,
                                          EvaluationCache* eval_cache) {
  switch (binop) {
    // (In-)Equality comparison.
    case ast::EQ:
    case ast::NE: {
      ASSIGN_OR_RETURN(EvalResult left, Eval(left_expr, entry, eval_cache));
      ASSIGN_OR_RETURN(EvalResult right, Eval(right_expr, entry, eval_cache));
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
      ASSIGN_OR_RETURN(Integer left, EvalToInt(left_expr, entry, eval_cache),
                       _ << " in ordered comparison");
      ASSIGN_OR_RETURN(Integer right, EvalToInt(right_expr, entry, eval_cache),
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
      ASSIGN_OR_RETURN(bool left_true,
                       EvalToBool(left_expr, entry, eval_cache));
      switch (binop) {
        case ast::AND:
          if (left_true)
            return EvalToBool(right_expr, entry, eval_cache);
          else
            return false;
        case ast::OR:
          if (left_true)
            return true;
          else
            return EvalToBool(right_expr, entry, eval_cache);
        case ast::IMPLIES:
          if (left_true)
            return EvalToBool(right_expr, entry, eval_cache);
          else
            return true;
        default:
          [[fallthrough]];
      }
    }

    default:
      return gutils::InternalErrorBuilder(GUTILS_LOC)
             << "unknown binary operator " << ast::BinaryOperator_Name(binop)
             << " encountered at runtime";
  }
}

struct EvalFieldAccess {
  const absl::string_view field;

  absl::Status Error(const std::string& type) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "value of type " << type << " has no field " << field;
  }

  absl::StatusOr<EvalResult> operator()(const Exact& exact) {
    if (field == "value") return {exact.value};
    return Error("exact");
  }

  absl::StatusOr<EvalResult> operator()(const Ternary& ternary) {
    if (field == "value") return {ternary.value};
    if (field == "mask") return {ternary.mask};
    return Error("ternary");
  }

  absl::StatusOr<EvalResult> operator()(const Lpm& lpm) {
    if (field == "value") return {lpm.value};
    if (field == "prefix_length") return {lpm.prefix_length};
    return Error("lpm");
  }

  absl::StatusOr<EvalResult> operator()(const Range& range) {
    if (field == "low") return {range.low};
    if (field == "high") return {range.high};
    return Error("range");
  }
  absl::StatusOr<EvalResult> operator()(bool) { return Error("bool"); }

  absl::StatusOr<EvalResult> operator()(const Integer&) { return Error("int"); }
};

// -- Main evaluator -----------------------------------------------------------

// Evaluates Expression over given table entry, returning EvalResult if
// successful or InternalError Status if a type mismatch is detected.
//
// Eval (without underscore) is a thin wrapper around Eval_, see further down;
// Eval_ should never be called directly, except by Eval.
absl::StatusOr<EvalResult> Eval_(const Expression& expr,
                                 const TableEntry& entry,
                                 EvaluationCache* eval_cache) {
  switch (expr.expression_case()) {
    case Expression::kBooleanConstant:
      return {expr.boolean_constant()};

    case Expression::kIntegerConstant: {
      mpz_class result;
      if (result.set_str(expr.integer_constant(), 10) == 0) return {result};
      return gutils::InternalErrorBuilder(GUTILS_LOC)
             << "AST invariant violated; invalid decimal string: "
             << expr.integer_constant();
    }

    case Expression::kKey: {
      auto it = entry.keys.find(expr.key());
      if (it == entry.keys.end()) {
        TypeError(expr.start_location(), expr.end_location())
            << "unknown key " << expr.key() << " in table " << entry.table_name;
      }
      return it->second;
    }

    case Expression::kMetadataAccess: {
      const std::string metadata_name = expr.metadata_access().metadata_name();
      if (metadata_name == "priority") {
        return Integer(entry.priority);
      } else {
        return TypeError(expr.start_location(), expr.end_location())
               << "unknown metadata '" << metadata_name << "'";
      }
    }

    case Expression::kBooleanNegation: {
      ASSIGN_OR_RETURN(bool result,
                       EvalToBool(expr.boolean_negation(), entry, eval_cache));
      return {!result};
    }

    case Expression::kArithmeticNegation: {
      ASSIGN_OR_RETURN(Integer result, EvalToInt(expr.arithmetic_negation(),
                                                 entry, eval_cache));
      return {-result};
    }

    case Expression::kTypeCast: {
      return EvalAndCastTo(expr.type(), expr.type_cast(), entry, eval_cache);
    }

    case Expression::kBinaryExpression: {
      const ast::BinaryExpression& binexpr = expr.binary_expression();
      return EvalBinaryExpression(binexpr.binop(), binexpr.left(),
                                  binexpr.right(), entry, eval_cache);
    }

    case Expression::kFieldAccess: {
      const Expression& composite_expr = expr.field_access().expr();
      const std::string& field = expr.field_access().field();
      ASSIGN_OR_RETURN(EvalResult composite_value,
                       Eval(composite_expr, entry, eval_cache));

      absl::StatusOr<EvalResult> result =
          absl::visit(EvalFieldAccess{.field = field}, composite_value);
      if (!result.ok()) {
        return TypeError(expr.start_location(), expr.end_location())
               << result.status().message();
      }
      return result;
    }

    case Expression::EXPRESSION_NOT_SET:
      break;
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << "invalid expression: " << expr.DebugString();
}

// -- Sanity checking ----------------------------------------------------------

// We wrap Eval_ with a cautionary dynamic type check to ease debugging.

absl::Status DynamicTypeCheck(const Expression& expr, const EvalResult result) {
  switch (expr.type().type_case()) {
    case Type::kBoolean:
      if (absl::holds_alternative<bool>(result)) return absl::OkStatus();
      break;
    case Type::kArbitraryInt:
    case Type::kFixedUnsigned:
      if (absl::holds_alternative<Integer>(result)) return absl::OkStatus();
      break;
    case Type::kExact:
      if (absl::holds_alternative<Exact>(result)) return absl::OkStatus();
      break;
    case Type::kTernary:
      if (absl::holds_alternative<Ternary>(result)) return absl::OkStatus();
      break;
    case Type::kLpm:
      if (absl::holds_alternative<Lpm>(result)) return absl::OkStatus();
      break;
    case Type::kRange:
      if (absl::holds_alternative<Range>(result)) return absl::OkStatus();
      break;
    case Type::kOptionalMatch:
      if (absl::holds_alternative<Ternary>(result)) return absl::OkStatus();
      break;
    case Type::kUnknown:
    case Type::kUnsupported:
    case Type::TYPE_NOT_SET:
      break;
  }
  return TypeError(expr.start_location(), expr.end_location())
         << "unexpected runtime representation of type " << expr.type();
}

// Wraps Eval_ with dynamic type check to ease debugging. Never call Eval_
// directly; call Eval instead. `eval_cache` is used for caching boolean results
// in order to avoid recomputation if an explanation is desired. Passing a
// nullptr will disable caching. Caching is implemented in EvalToBool.
absl::StatusOr<EvalResult> Eval(const Expression& expr, const TableEntry& entry,
                                EvaluationCache* eval_cache) {
  ASSIGN_OR_RETURN(EvalResult result, Eval_(expr, entry, eval_cache));
  RETURN_IF_ERROR(DynamicTypeCheck(expr, result));
  return result;
}

}  // namespace internal_interpreter

// -- Public interface ---------------------------------------------------------

absl::StatusOr<bool> EntryMeetsConstraint(const p4::v1::TableEntry& entry,
                                          const ConstraintInfo& context) {
  using ::p4_constraints::internal_interpreter::EvalToBool;
  using ::p4_constraints::internal_interpreter::P4IDToString;
  using ::p4_constraints::internal_interpreter::ParseEntry;
  using ::p4_constraints::internal_interpreter::TableEntry;

  // Find table associated with entry and parse the entry.
  auto it = context.find(entry.table_id());
  if (it == context.end())
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "table entry with unknown table ID "
           << P4IDToString(entry.table_id());
  const TableInfo& table_info = it->second;
  ASSIGN_OR_RETURN(TableEntry parsed_entry, ParseEntry(entry, table_info),
                   _ << " while parsing P4RT table entry for table '"
                     << table_info.name << "':");

  // Check if entry satisfies table constraint (if present).
  if (!table_info.constraint.has_value()) {
    VLOG(1) << "Table \"" << table_info.name
            << "\" has no constraint; accepting entry unconditionally.";
    return true;
  }
  const Expression& constraint = table_info.constraint.value();
  if (constraint.type().type_case() != Type::kBoolean) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "table " << table_info.name
           << " has non-boolean constraint: " << constraint.DebugString();
  }
  // No explanation is returned so no cache is provided.
  return EvalToBool(constraint, parsed_entry, /*eval_cache=*/nullptr);
}

}  // namespace p4_constraints
