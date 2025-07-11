// Copyright 2020 The P4-Constraints Authors
// SPDX-License-Identifier: Apache-2.0
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
#include <stdint.h>

#include <cstring>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/meta/type_traits.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "gutil/ordered_map.h"
#include "gutil/overload.h"
#include "gutil/status.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/backend/errors.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/quote.h"
#include "p4_constraints/ret_check.h"

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

std::string EvalResultToString(const EvalResult& result) {
  return absl::visit(
      gutil::Overload{
          [](bool result) -> std::string { return result ? "true" : "false"; },
          [](const Integer& result) { return result.get_str(); },
          [](const Exact& result) {
            return absl::StrFormat("Exact{.value = %s}",
                                   result.value.get_str());
          },
          [](const Ternary& result) {
            return absl::StrFormat("Ternary{.value = %s, .mask = %s}",
                                   result.value.get_str(),
                                   result.mask.get_str());
          },
          [](const Lpm& result) {
            return absl::StrFormat("Lpm{.value = %s, .prefix_length = %s}",
                                   result.value.get_str(),
                                   result.prefix_length.get_str());
          },
          [](const Range& result) {
            return absl::StrFormat("Range{.low = %s, .high = %s}",
                                   result.low.get_str(), result.high.get_str());
          }},
      result);
}

// -- Parsing P4RT table entries -----------------------------------------------

Integer ParseP4RTInteger(std::string int_str) {
  // Remove leading zero-bits, to properly convert to a c_str in next step,
  // allowing for non-canonical bytestrings.
  int_str.erase(0, int_str.find_first_not_of('\0'));
  mpz_class integer;
  constexpr int most_significant_first = 1;
  constexpr size_t char_size = sizeof(char);
  static_assert(char_size == 1, "expected sizeof(char) == 1");
  constexpr int endian = 0;    // system default
  constexpr size_t nails = 0;  // don't skip any bits
  mpz_import(integer.get_mpz_t(), int_str.size(), most_significant_first,
             char_size, endian, nails, int_str.data());
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
    return gutil::InvalidArgumentErrorBuilder()
           << "unknown table key with ID " << P4IDToString(p4field.field_id());
  }
  const KeyInfo& key = it->second;

  switch (p4field.field_match_type_case()) {
    case p4::v1::FieldMatch::kExact: {
      RET_CHECK_EQ(key.type.type_case(), Type::kExact)
          << "P4RT table entry inconsistent with P4 program";
      Integer value = ParseP4RTInteger(p4field.exact().value());
      return {std::make_pair(key.name, Exact{.value = value})};
    }

    case p4::v1::FieldMatch::kTernary: {
      RET_CHECK_EQ(key.type.type_case(), Type::kTernary)
          << "P4RT table entry inconsistent with P4 program";
      Integer value = ParseP4RTInteger(p4field.ternary().value());
      Integer mask = ParseP4RTInteger(p4field.ternary().mask());
      return {std::make_pair(key.name, Ternary{.value = value, .mask = mask})};
    }

    case p4::v1::FieldMatch::kLpm: {
      RET_CHECK_EQ(key.type.type_case(), Type::kLpm)
          << "P4RT table entry inconsistent with P4 program";
      Integer value = ParseP4RTInteger(p4field.lpm().value());
      Integer prefix_len = mpz_class(p4field.lpm().prefix_len());
      return {std::make_pair(key.name,
                             Lpm{.value = value, .prefix_length = prefix_len})};
    }

    case p4::v1::FieldMatch::kRange: {
      RET_CHECK_EQ(key.type.type_case(), Type::kRange)
          << "P4RT table entry inconsistent with P4 program";

      Integer low = ParseP4RTInteger(p4field.range().low());
      Integer high = ParseP4RTInteger(p4field.range().high());
      return {std::make_pair(key.name, Range{.low = low, .high = high})};
    }

    case p4::v1::FieldMatch::kOptional: {
      RET_CHECK_EQ(key.type.type_case(), Type::kOptionalMatch)
          << "P4RT table entry inconsistent with P4 program";
      Integer value = ParseP4RTInteger(p4field.optional().value());
      return {std::make_pair(
          key.name, Ternary{.value = value,
                            .mask = MaxValueForBitwidth(
                                key.type.optional_match().bitwidth())})};
    }

    default:
      return gutil::InvalidArgumentErrorBuilder()
             << "unsupported P4RT field match type "
             << p4field.field_match_type_case();
  }
}

absl::StatusOr<EvaluationContext> ParseTableEntry(
    const p4::v1::TableEntry& entry, const TableInfo& table_info) {
  absl::flat_hash_map<std::string, EvalResult> keys;

  // Parse all keys that are explicitly present.
  for (const p4::v1::FieldMatch& field : entry.match()) {
    ASSIGN_OR_RETURN(auto kv, ParseKey(field, table_info));
    auto result = keys.insert(kv);
    if (result.second == false) {
      return gutil::InvalidArgumentErrorBuilder()
             << "duplicate match on key " << kv.first << " with ID "
             << P4IDToString(field.field_id());
    }
  }

  // Use default value for omitted keys.
  // See Section 9.1.1. of the P4Runtime specification.
  for (const auto& [name, key_info] : table_info.keys_by_name) {
    if (keys.contains(name)) continue;
    switch (key_info.type.type_case()) {
      case ast::Type::kExact:
        return gutil::InvalidArgumentErrorBuilder()
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
    return gutil::InternalErrorBuilder()
           << "Key '" << key_info.name
           << "' of invalid match type detected at runtime: "
           << key_info.type.DebugString();
  }

  TableEntry table_entry{
      .table_name = table_info.name,
      .priority = entry.priority(),
      .keys = std::move(keys),
  };

  return EvaluationContext{
      .constraint_context = std::move(table_entry),
      .constraint_source = table_info.constraint_source,
  };
}

absl::StatusOr<EvaluationContext> ParseAction(const p4::v1::Action& action,
                                              const ActionInfo& action_info) {
  absl::flat_hash_map<std::string, Integer> action_parameters;

  // Parse action parameters.
  for (const p4::v1::Action_Param& param : action.params()) {
    int32_t param_id = param.param_id();
    Integer param_value = ParseP4RTInteger(param.value());
    auto it = action_info.params_by_id.find(param_id);
    if (it == action_info.params_by_id.end()) {
      return gutil::InvalidArgumentErrorBuilder()
             << "unknown action param with ID " << P4IDToString(param_id);
    }
    if (action_parameters.contains(it->second.name)) {
      return gutil::InvalidArgumentErrorBuilder()
             << "duplicate action param with ID " << P4IDToString(param_id);
    }
    action_parameters[it->second.name] = param_value;
  }
  ActionInvocation action_invocation{
      .action_id = action.action_id(),
      .action_name = action_info.name,
      .action_parameters = std::move(action_parameters),
  };
  return EvaluationContext{
      .constraint_context = std::move(action_invocation),
      .constraint_source = action_info.constraint_source,
  };
}

// -- Auxiliary evaluators -----------------------------------------------------

// Like Eval, but ensuring the result is a bool. Caches Boolean results and
// checks cache before evaluation to avoid recomputation.
absl::StatusOr<bool> EvalToBool(const Expression& expr,
                                const EvaluationContext& context,
                                EvaluationCache* eval_cache) {
  if (eval_cache != nullptr) {
    auto cache_result = eval_cache->find(&expr);
    if (cache_result != eval_cache->end()) return cache_result->second;
  }
  ASSIGN_OR_RETURN(EvalResult result, Eval(expr, context, eval_cache));
  if (absl::holds_alternative<bool>(result)) {
    if (eval_cache != nullptr)
      eval_cache->insert({&expr, absl::get<bool>(result)});
    return absl::get<bool>(result);
  } else {
    return RuntimeTypeError(context.constraint_source, expr.start_location(),
                            expr.end_location())
           << "expected expression of type bool";
  }
}

// Like Eval, but ensuring the result is an Integer.
absl::StatusOr<Integer> EvalToInt(const Expression& expr,
                                  const EvaluationContext& context,
                                  EvaluationCache* eval_cache) {
  ASSIGN_OR_RETURN(EvalResult result, Eval(expr, context, eval_cache));
  if (absl::holds_alternative<Integer>(result))
    return absl::get<Integer>(result);
  return RuntimeTypeError(context.constraint_source, expr.start_location(),
                          expr.end_location())
         << "expected expression of integral type";
}

absl::StatusOr<EvalResult> EvalAndCastTo(const Type& type,
                                         const Expression& expr,
                                         const EvaluationContext& context,
                                         EvaluationCache* eval_cache) {
  ASSIGN_OR_RETURN(EvalResult result, Eval(expr, context, eval_cache));
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
  return RuntimeTypeError(context.constraint_source, expr.start_location(),
                          expr.end_location())
         << "cannot cast expression of type " << expr.type() << " to type "
         << type;
}

absl::StatusOr<bool> EvalBinaryExpression(ast::BinaryOperator binop,
                                          const Expression& left_expr,
                                          const Expression& right_expr,
                                          const EvaluationContext& context,
                                          EvaluationCache* eval_cache) {
  switch (binop) {
    // (In-)Equality comparison.
    case ast::EQ:
    case ast::NE: {
      ASSIGN_OR_RETURN(EvalResult left, Eval(left_expr, context, eval_cache));
      ASSIGN_OR_RETURN(EvalResult right, Eval(right_expr, context, eval_cache));
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
      ASSIGN_OR_RETURN(Integer left, EvalToInt(left_expr, context, eval_cache),
                       _ << " in ordered comparison");
      ASSIGN_OR_RETURN(Integer right,
                       EvalToInt(right_expr, context, eval_cache),
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
                       EvalToBool(left_expr, context, eval_cache));
      switch (binop) {
        case ast::AND:
          if (left_true)
            return EvalToBool(right_expr, context, eval_cache);
          else
            return false;
        case ast::OR:
          if (left_true)
            return true;
          else
            return EvalToBool(right_expr, context, eval_cache);
        case ast::IMPLIES:
          if (left_true)
            return EvalToBool(right_expr, context, eval_cache);
          else
            return true;
        default:
          [[fallthrough]];
      }
    }

    default:
      return gutil::InternalErrorBuilder()
             << "unknown binary operator " << ast::BinaryOperator_Name(binop)
             << " encountered at runtime";
  }
}

struct EvalFieldAccess {
  const absl::string_view field;

  absl::Status Error(const std::string& type) {
    return gutil::InvalidArgumentErrorBuilder()
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

// -- Explainer ----------------------------------------------------------------

absl::StatusOr<const Expression*> MinimalSubexpressionLeadingToEvalResult(
    const Expression& expression, const EvaluationContext& context,
    EvaluationCache& eval_cache, ast::SizeCache& size_cache) {
  switch (expression.expression_case()) {
    case Expression::kBooleanConstant:
      return &expression;

    case Expression::kBooleanNegation: {
      return MinimalSubexpressionLeadingToEvalResult(
          expression.boolean_negation(), context, eval_cache, size_cache);
    }

    case Expression::kBinaryExpression: {
      const ast::BinaryExpression& binexpr = expression.binary_expression();
      const ast::BinaryOperator& binop = binexpr.binop();
      switch (binop) {
        // Search terminates on non-boolean comparisons because descendants
        // are all non-boolean, so no refinement is possible.
        case ast::EQ:
        case ast::NE:
        case ast::GT:
        case ast::GE:
        case ast::LT:
        case ast::LE:
          return &expression;

        // Boolean comparisons may require further search to find minimal
        // reason, if no such refinement is possible, terminate search.
        // AND      was  False -> search false component(s)
        // OR       was  True  -> search true component(s)
        // IMPLIES  was  True  -> search false antecedent and/or true consequent
        // AND      was  True  -> terminate search
        // OR       was  False -> terminate search
        // IMPLIES  was  False -> terminate search
        case ast::AND:
        case ast::OR:
        case ast::IMPLIES: {
          ASSIGN_OR_RETURN(bool left_result_is_true,
                           EvalToBool(binexpr.left(), context, &eval_cache));
          ASSIGN_OR_RETURN(bool right_result_is_true,
                           EvalToBool(binexpr.right(), context, &eval_cache));

          std::vector<const Expression*> candidate_subexpressions;

          switch (binop) {
            case ast::AND: {
              if (!left_result_is_true)
                candidate_subexpressions.push_back(&binexpr.left());
              if (!right_result_is_true)
                candidate_subexpressions.push_back(&binexpr.right());
              break;
            }
            case ast::OR: {
              if (left_result_is_true)
                candidate_subexpressions.push_back(&binexpr.left());
              if (right_result_is_true)
                candidate_subexpressions.push_back(&binexpr.right());
              break;
            }
            case ast::IMPLIES: {
              if (!left_result_is_true)
                candidate_subexpressions.push_back(&binexpr.left());
              if (right_result_is_true)
                candidate_subexpressions.push_back(&binexpr.right());
              break;
            }
            default:
              return gutil::InternalErrorBuilder()
                     << "unreachable code reached";
          }

          if (candidate_subexpressions.empty()) return &expression;
          // Returns `MinimalSubexpressionLeadingToEvalResult` of sole
          // candidate.
          if (candidate_subexpressions.size() == 1) {
            return MinimalSubexpressionLeadingToEvalResult(
                *candidate_subexpressions[0], context, eval_cache, size_cache);
          }
          // Returns the `MinimalSubexpressionLeadingToEvalResult` from the
          // candidate who has the smallest such subexpression.
          ASSIGN_OR_RETURN(auto* subexpression_0,
                           MinimalSubexpressionLeadingToEvalResult(
                               *candidate_subexpressions[0], context,
                               eval_cache, size_cache));
          ASSIGN_OR_RETURN(auto* subexpression_1,
                           MinimalSubexpressionLeadingToEvalResult(
                               *candidate_subexpressions[1], context,
                               eval_cache, size_cache));
          ASSIGN_OR_RETURN(int size_0,
                           ast::Size(*subexpression_0, &size_cache));
          ASSIGN_OR_RETURN(int size_1,
                           ast::Size(*subexpression_1, &size_cache));
          return size_0 <= size_1 ? subexpression_0 : subexpression_1;
        }

        default:
          return gutil::InternalErrorBuilder()
                 << "unknown binary operator "
                 << ast::BinaryOperator_Name(binop)
                 << " encountered at runtime";
      }
    }

    default:
      return gutil::InternalErrorBuilder()
             << "Explanation search should terminate at boolean expressions\n "
             << "Non-boolean expression reached: " << expression.DebugString();
  }
}

// Returns human readable explanation of constraint violation.
absl::StatusOr<std::string> ExplainConstraintViolation(
    const Expression& expr, const EvaluationContext& context,
    EvaluationCache& eval_cache, ast::SizeCache& size_cache) {
  ASSIGN_OR_RETURN(const ast::Expression* explanation,
                   MinimalSubexpressionLeadingToEvalResult(
                       expr, context, eval_cache, size_cache));
  ASSIGN_OR_RETURN(bool truth_value,
                   EvalToBool(*explanation, context, &eval_cache));
  ASSIGN_OR_RETURN(std::string reason,
                   QuoteSubConstraint(context.constraint_source,
                                      explanation->start_location(),
                                      explanation->end_location()));

  const absl::flat_hash_set<std::string> relevant_fields =
      ast::GetVariables(*explanation);
  return std::visit(
      gutil::Overload{
          [&](const TableEntry& table_entry) -> std::string {
            // Ordered for determinism when golden testing.
            std::string key_info = absl::StrJoin(
                gutil::AsOrderedView(table_entry.keys), "",
                [&](std::string* out,
                    const std::pair<std::string, EvalResult>& pair) {
                  if (relevant_fields.contains(pair.first)) {
                    absl::StrAppend(
                        out, "Field: \"", pair.first,
                        "\" -> Value: ", EvalResultToString(pair.second), "\n");
                  }
                });
            return absl::StrFormat(
                "All entries must %ssatisfy:"
                "\n\n%s\n"
                "But your entry does%s.\n"
                ">>>Relevant Entry Info<<<\n"
                "Table Name: \"%s\"\n"
                "Priority:%d\n"
                "%s",
                (truth_value ? "not " : ""), reason,
                (truth_value ? "" : " not"), table_entry.table_name,
                table_entry.priority, key_info);
          },
          [&](const ActionInvocation& action_invocation) -> std::string {
            std::string param_info = absl::StrJoin(
                gutil::AsOrderedView(action_invocation.action_parameters), "",
                [&](std::string* out,
                    const std::pair<std::string, Integer>& pair) {
                  if (relevant_fields.contains(pair.first)) {
                    absl::StrAppend(out, "Param name: \"", pair.first,
                                    "\" -> Value: ", pair.second.get_str(),
                                    "\n");
                  }
                });
            return absl::StrFormat(
                "All actions must %ssatisfy:"
                "\n\n%s\n"
                "But your entry does%s.\n"
                ">>>Relevant Action Info<<<\n"
                "Action Name: \"%s\"\n"
                "%s",
                (truth_value ? "not " : ""), reason,
                (truth_value ? "" : " not"), action_invocation.action_name,
                param_info);
          },
      },
      context.constraint_context);
}
// -- Main evaluator -----------------------------------------------------------

// Evaluates Expression over given table entry, returning EvalResult if
// successful or InternalError Status if a type mismatch is detected.
//
// Eval (without underscore) is a thin wrapper around Eval_, see further down;
// Eval_ should never be called directly, except by Eval.
absl::StatusOr<EvalResult> Eval_(const Expression& expr,
                                 const EvaluationContext& context,
                                 EvaluationCache* eval_cache) {
  switch (expr.expression_case()) {
    case Expression::kBooleanConstant:
      return {expr.boolean_constant()};

    case Expression::kIntegerConstant: {
      mpz_class result;
      if (result.set_str(expr.integer_constant(), 10) == 0) return {result};
      return gutil::InternalErrorBuilder()
             << "AST invariant violated; invalid decimal string: "
             << expr.integer_constant();
    }

    case Expression::kKey: {
      const TableEntry* table_entry =
          std::get_if<TableEntry>(&context.constraint_context);
      if (table_entry == nullptr) {
        return RuntimeTypeError(context.constraint_source,
                                expr.start_location(), expr.end_location())
               << "Found a reference to a key in an action constraint.";
      }

      auto it = table_entry->keys.find(expr.key());
      if (it == table_entry->keys.end()) {
        return RuntimeTypeError(context.constraint_source,
                                expr.start_location(), expr.end_location())
               << "unknown key " << expr.key() << " in table "
               << table_entry->table_name;
      }
      return it->second;
    }

    case Expression::kActionParameter: {
      const ActionInvocation* action_invocation =
          std::get_if<ActionInvocation>(&context.constraint_context);
      if (action_invocation == nullptr) {
        return RuntimeTypeError(context.constraint_source,
                                expr.start_location(), expr.end_location())
               << "Found a reference to an action parameter in a table "
                  "constraint.";
      }
      auto it =
          action_invocation->action_parameters.find(expr.action_parameter());
      if (it == action_invocation->action_parameters.end()) {
        return RuntimeTypeError(context.constraint_source,
                                expr.start_location(), expr.end_location())
               << "unknown action parameter " << expr.action_parameter()
               << " in action " << action_invocation->action_name;
      }
      return it->second;
    }

    case Expression::kAttributeAccess: {
      const TableEntry* table_entry =
          std::get_if<TableEntry>(&context.constraint_context);
      if (table_entry == nullptr) {
        return RuntimeTypeError(context.constraint_source,
                                expr.start_location(), expr.end_location())
               << "The constraint context does not contain a TableEntry.";
      }
      const std::string attribute_name =
          expr.attribute_access().attribute_name();
      if (attribute_name == "priority") {
        return Integer(table_entry->priority);
      } else {
        return RuntimeTypeError(context.constraint_source,
                                expr.start_location(), expr.end_location())
               << "unknown attribute '" << attribute_name << "'";
      }
    }

    case Expression::kBooleanNegation: {
      ASSIGN_OR_RETURN(bool result, EvalToBool(expr.boolean_negation(), context,
                                               eval_cache));
      return {!result};
    }

    case Expression::kArithmeticNegation: {
      ASSIGN_OR_RETURN(Integer result, EvalToInt(expr.arithmetic_negation(),
                                                 context, eval_cache));
      return {-result};
    }

    case Expression::kTypeCast: {
      return EvalAndCastTo(expr.type(), expr.type_cast(), context, eval_cache);
    }

    case Expression::kBinaryExpression: {
      const ast::BinaryExpression& binexpr = expr.binary_expression();
      return EvalBinaryExpression(binexpr.binop(), binexpr.left(),
                                  binexpr.right(), context, eval_cache);
    }

    case Expression::kFieldAccess: {
      const Expression& composite_expr = expr.field_access().expr();
      const std::string& field = expr.field_access().field();
      ASSIGN_OR_RETURN(EvalResult composite_value,
                       Eval(composite_expr, context, eval_cache));

      absl::StatusOr<EvalResult> result =
          absl::visit(EvalFieldAccess{.field = field}, composite_value);
      if (!result.ok()) {
        return RuntimeTypeError(context.constraint_source,
                                expr.start_location(), expr.end_location())
               << result.status().message();
      }
      return result;
    }

    case Expression::EXPRESSION_NOT_SET:
      break;
  }
  return gutil::InvalidArgumentErrorBuilder()
         << "invalid expression: " << expr.DebugString();
}

// -- Sanity checking ----------------------------------------------------------

// We wrap Eval_ with a cautionary dynamic type check to ease debugging.

absl::Status DynamicTypeCheck(const ConstraintSource& source,
                              const Expression& expr, const EvalResult result) {
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
  return RuntimeTypeError(source, expr.start_location(), expr.end_location())
         << "unexpected runtime representation of type " << expr.type();
}

// Wraps Eval_ with dynamic type check to ease debugging. Never call Eval_
// directly; call Eval instead. `eval_cache` is used for caching boolean results
// in order to avoid recomputation if an explanation is desired. Passing a
// nullptr will disable caching. Caching is implemented in EvalToBool.
absl::StatusOr<EvalResult> Eval(const Expression& expr,
                                const EvaluationContext& context,
                                EvaluationCache* eval_cache) {
  ASSIGN_OR_RETURN(EvalResult result, Eval_(expr, context, eval_cache));
  RETURN_IF_ERROR(DynamicTypeCheck(context.constraint_source, expr, result));
  return result;
}

absl::StatusOr<std::string> ReasonEntryViolatesConstraint(
    const p4::v1::Action& action, const ConstraintInfo& constraint_info) {
  const uint32_t action_id = action.action_id();
  auto* action_info = GetActionInfoOrNull(constraint_info, action_id);
  if (action_info == nullptr) {
    return gutil::InvalidArgumentErrorBuilder()
           << "action entry with unknown action ID " << P4IDToString(action_id);
  }
  // Check if action has an action restriction.
  if (!action_info->constraint.has_value()) return "";

  const Expression& constraint = *action_info->constraint;
  if (constraint.type().type_case() != Type::kBoolean) {
    return gutil::InvalidArgumentErrorBuilder()
           << "action " << action_info->name
           << " has non-boolean constraint: " << constraint.DebugString();
  }

  EvaluationCache eval_cache;
  ast::SizeCache size_cache;
  ASSIGN_OR_RETURN(const EvaluationContext eval_context,
                   ParseAction(action, *action_info),
                   _ << " while parsing P4RT table entry for action '"
                     << action_info->name << "':");

  ASSIGN_OR_RETURN(bool entry_meets_constraint,
                   EvalToBool(constraint, eval_context, &eval_cache));
  if (!entry_meets_constraint) {
    return ExplainConstraintViolation(constraint, eval_context, eval_cache,
                                      size_cache);
  }
  return "";
}

absl::StatusOr<std::string> ReasonEntryViolatesConstraint(
    const p4::v1::ActionProfileActionSet& action_set,
    const ConstraintInfo& constraint_info) {
  for (const p4::v1::ActionProfileAction& action_profile_action :
       action_set.action_profile_actions()) {
    ASSIGN_OR_RETURN(std::string reason,
                     ReasonEntryViolatesConstraint(
                         action_profile_action.action(), constraint_info));
    if (!reason.empty()) return reason;
  }
  return "";
}

}  // namespace internal_interpreter

// -- Public interface ---------------------------------------------------------

absl::StatusOr<std::string> ReasonEntryViolatesConstraint(
    const p4::v1::TableEntry& entry, const ConstraintInfo& constraint_info) {
  using ::p4_constraints::internal_interpreter::EvalToBool;
  using ::p4_constraints::internal_interpreter::EvaluationCache;
  using ::p4_constraints::internal_interpreter::EvaluationContext;
  using ::p4_constraints::internal_interpreter::ExplainConstraintViolation;
  using ::p4_constraints::internal_interpreter::P4IDToString;
  using ::p4_constraints::internal_interpreter::ParseAction;
  using ::p4_constraints::internal_interpreter::ParseTableEntry;
  using ::p4_constraints::internal_interpreter::TableEntry;

  // Find table associated with entry.
  auto* table_info = GetTableInfoOrNull(constraint_info, entry.table_id());
  if (table_info == nullptr) {
    return gutil::InvalidArgumentErrorBuilder()
           << "table entry with unknown table ID "
           << P4IDToString(entry.table_id());
  }
  // Check if entry satisfies table constraint (if present).
  if (table_info->constraint.has_value()) {
    const Expression& constraint = table_info->constraint.value();
    if (constraint.type().type_case() != Type::kBoolean) {
      return gutil::InvalidArgumentErrorBuilder()
             << "table " << table_info->name
             << " has non-boolean constraint: " << constraint.DebugString();
    }
    // Parse entry and check constraint.
    ASSIGN_OR_RETURN(const EvaluationContext eval_context,
                     ParseTableEntry(entry, *table_info),
                     _ << " while parsing P4RT table entry for table '"
                       << table_info->name << "':");
    EvaluationCache eval_cache;
    ast::SizeCache size_cache;
    ASSIGN_OR_RETURN(bool entry_satisfies_constraint,
                     EvalToBool(constraint, eval_context, &eval_cache));

    if (!entry_satisfies_constraint) {
      return ExplainConstraintViolation(constraint, eval_context, eval_cache,
                                        size_cache);
    }
  }

  if (!entry.has_action()) return "";

  switch (entry.action().type_case()) {
    case p4::v1::TableAction::kAction:
      return internal_interpreter::ReasonEntryViolatesConstraint(
          entry.action().action(), constraint_info);
    case p4::v1::TableAction::kActionProfileMemberId:
    case p4::v1::TableAction::kActionProfileGroupId:
      return gutil::InvalidArgumentErrorBuilder()
             << "action restrictions not supported for entries with the given "
                "kind of action: "
             << entry.DebugString();
    case p4::v1::TableAction::kActionProfileActionSet: {
      return internal_interpreter::ReasonEntryViolatesConstraint(
          entry.action().action_profile_action_set(), constraint_info);
    }
    case p4::v1::TableAction::TYPE_NOT_SET:
      break;
  }
  return gutil::InvalidArgumentErrorBuilder()
         << "unknown action type " << entry.action().type_case();
}

}  // namespace p4_constraints
