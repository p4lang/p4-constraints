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

#include "p4_constraints/backend/type_checker.h"

#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "gutils/source_location.h"
#include "gutils/status.h"
#include "gutils/status_builder.h"
#include "gutils/status_macros.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/quote.h"

namespace p4_constraints {

namespace {

using ::p4_constraints::ast::BinaryExpression;
using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::SourceLocation;
using ::p4_constraints::ast::Type;

// -- Error handling -----------------------------------------------------------

gutils::StatusBuilder StaticTypeError(const ConstraintSource& source,
                                      const SourceLocation& start,
                                      const SourceLocation& end) {
  absl::StatusOr<std::string> quote = QuoteSubConstraint(source, start, end);
  if (!quote.ok()) {
    return gutils::InternalErrorBuilder(GUTILS_LOC)
           << "Failed to quote sub-constraint: "
           << gutils::StableStatusToString(quote.status());
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << *quote << "Type error: ";
}

gutils::StatusBuilder InternalError(const ConstraintSource& source,
                                    const SourceLocation& start,
                                    const SourceLocation& end) {
  absl::StatusOr<std::string> quote = QuoteSubConstraint(source, start, end);
  if (!quote.ok()) {
    return gutils::InternalErrorBuilder(GUTILS_LOC)
           << "Failed to quote sub-constraint: "
           << gutils::StableStatusToString(quote.status());
  }
  return gutils::InternalErrorBuilder(GUTILS_LOC)
         << *quote << "Internal error: ";
}

// -- Castability & Unification ------------------------------------------------

// Castability of types is given by the following Hasse diagram, where lower
// types can be cast to higher types (but not vice versa):
//
//   exact<W>  ternary<W>  lpm<W>  range<W>  optional<W>
//           \_________ \ /  _____/_________/
//                     bit<W>
//                       |
//                  arbitrary_int
//
// Types missing from the diagram cannot be cast to any other types. Formally,
// castability is a partial order on types.

// Strictly greater than with respect to castability order above.
bool StrictlyAboveInCastabilityOrder(const Type& left, const Type& right) {
  switch (left.type_case()) {
    case Type::kExact:
    case Type::kTernary:
    case Type::kLpm:
    case Type::kRange:
    case Type::kOptionalMatch:
      switch (right.type_case()) {
        case Type::kFixedUnsigned:
          return TypeBitwidth(left) == TypeBitwidth(right);
        case Type::kArbitraryInt:
          return true;
        default:
          return false;
      }
    case Type::kFixedUnsigned:
      return right.type_case() == Type::kArbitraryInt;
    default:
      return false;
  }
}
// Returns true if 'left' is exactly one level above 'right' in the castability
// order. This ensures that casts only move one level up the Hasse diagram.
bool OneLevelAboveInCastabilityOrder(const Type& left, const Type& right) {
  // Check if left is strictly above right in the castability order
  if (!StrictlyAboveInCastabilityOrder(left, right)) {
    return false;
  }

  // Now check that there isn't an intermediate type between them
  // For the specific Hasse diagram used in P4-Constraints:

  // Case 1: right is arbitrary_int, left must be fixed_unsigned
  if (right.type_case() == Type::kArbitraryInt) {
    return left.type_case() == Type::kFixedUnsigned;
  }

  // Case 2: right is fixed_unsigned, left must be one of the match types
  if (right.type_case() == Type::kFixedUnsigned) {
    return left.type_case() == Type::kExact ||
           left.type_case() == Type::kTernary ||
           left.type_case() == Type::kLpm || left.type_case() == Type::kRange ||
           left.type_case() == Type::kOptionalMatch;
  }

  // No other valid one-level jumps in the hierarchy
  return false;
}
// Returns the least upper bound of the given types in the castability ordering.
//
// The least upper bound (join, supremum) is the lowest common ancestor of the
// two types in the castability diagram above, where an ancestor is a type
// reachable via am upward path. Note that such a supremum (common ancestor)
// does not exist for all pairs of types.
absl::optional<Type> LeastUpperBound(const Type& left, const Type& right) {
  if (left == right) return left;
  if (StrictlyAboveInCastabilityOrder(left, right)) return left;
  if (StrictlyAboveInCastabilityOrder(right, left)) return right;
  // While it is not true for partial orders in general that
  // LeastUpperBound(x,y) exists iff x >= y or y >= x, it is true for our
  // castability relation.
  return absl::nullopt;
}

// Mutates the input expression, wrapping it with a type_cast to the given type.
void WrapWithCast(Expression* expr, Type type) {
  Expression cast;
  *cast.mutable_start_location() = expr->start_location();
  *cast.mutable_end_location() = expr->end_location();
  *cast.mutable_type() = type;
  // Need std::move to make this an O(1)-operation; copying would be O(|expr|).
  *cast.mutable_type_cast() = std::move(*expr);
  *expr = std::move(cast);
}

// Mutates the input expression, wrapping it with a chain of zero or more type
// casts to convert it, possibly transitively, to the given target type.
absl::Status CastTransitivelyTo(Expression* expr, Type target_type) {
  if (StrictlyAboveInCastabilityOrder(target_type, expr->type()) &&
      expr->type().type_case() == Type::kArbitraryInt) {
    // Insert int ~~> bit<W> cast.
    Type fixed_unsigned;
    auto bitwidth = TypeBitwidth(target_type).value_or(-1);
    DCHECK_NE(bitwidth, -1) << "cannot cast to arbitrary-size type";
    fixed_unsigned.mutable_fixed_unsigned()->set_bitwidth(bitwidth);
    WrapWithCast(expr, fixed_unsigned);
  }

  if (StrictlyAboveInCastabilityOrder(target_type, expr->type()) &&
      expr->type().type_case() == Type::kFixedUnsigned) {
    // Insert bit<W> ~~> Exact<W>/Ternary<W>/LPM<W>/Range<W>/Optional<W> cast.
    WrapWithCast(expr, target_type);
  }

  DCHECK_EQ(expr->type(), target_type) << "unification did not unify types";
  return absl::OkStatus();
}

// Attempts to unify the types of the given expressions, returning the
// resulting type if unification succeeds, or an InvalidArgument Status
// otherwise.
//
// Precondition: The arguments have been successfully type checked.
// Postcondition: left.type() == right.type() == <return value>.
//
// If left.type() == right.type() initially, Unify returns successfully
// without mutations. If left.type() != right.type() initially, and
// LeastUpperBound(left.type(), right.type()) exists, Unify returns successfully
// and mutates the expressions by wrapping them with type casts to the least
// upper bound. Otherwise, Unify returns an InvalidArgument Status.
absl::StatusOr<Type> Unify(Expression* left, Expression* right,
                           const ConstraintSource& constraint_source) {
  const absl::optional<Type> least_upper_bound =
      LeastUpperBound(left->type(), right->type());
  if (!least_upper_bound.has_value()) {
    return StaticTypeError(constraint_source, left->start_location(),
                           right->end_location())
           << "cannot unify types " << left->type() << " and " << right->type();
  }
  RETURN_IF_ERROR(CastTransitivelyTo(left, *least_upper_bound));
  RETURN_IF_ERROR(CastTransitivelyTo(right, *least_upper_bound));
  return *least_upper_bound;
}

// -- Field accesses (aka projections) --------------------------------------

using CompositeTypeAndField = std::tuple<Type::TypeCase, std::string>;

// (composite type, field name) -> field type.
const auto* const kFieldTypes =
    new absl::flat_hash_map<CompositeTypeAndField, const Type::TypeCase>{
        {std::make_tuple(Type::kExact, "value"), Type::kFixedUnsigned},
        {std::make_tuple(Type::kTernary, "value"), Type::kFixedUnsigned},
        {std::make_tuple(Type::kTernary, "mask"), Type::kFixedUnsigned},
        {std::make_tuple(Type::kLpm, "value"), Type::kFixedUnsigned},
        {std::make_tuple(Type::kLpm, "prefix_length"), Type::kArbitraryInt},
        {std::make_tuple(Type::kRange, "low"), Type::kFixedUnsigned},
        {std::make_tuple(Type::kRange, "high"), Type::kFixedUnsigned},
        {std::make_tuple(Type::kOptionalMatch, "value"), Type::kFixedUnsigned},
        {std::make_tuple(Type::kOptionalMatch, "mask"), Type::kFixedUnsigned},
    };

absl::optional<Type> FieldTypeOfCompositeType(const Type& composite_type,
                                              const std::string& field) {
  auto it =
      kFieldTypes->find(std::make_tuple(composite_type.type_case(), field));
  if (it == kFieldTypes->end()) return {};
  Type field_type = TypeCaseToType(it->second);
  absl::optional<int> bitwidth = TypeBitwidth(composite_type);
  if (!bitwidth.has_value()) {
    LOG(ERROR) << "expected composite type " << composite_type
               << " to have bitwidth";
  }
  SetTypeBitwidth(&field_type, bitwidth.value_or(-1));
  return {field_type};
}

}  // namespace

// -- Type checking ------------------------------------------------------------

const ConstraintSource& GetConstraintSource(const ActionInfo* action_info,
                                            const TableInfo* table_info) {
  if (action_info == nullptr) return table_info->constraint_source;
  return action_info->constraint_source;
}

absl::Status InferAndCheckTypes(Expression* expr, const ActionInfo* action_info,
                                const TableInfo* table_info) {
  const ConstraintSource& constraint_source =
      GetConstraintSource(action_info, table_info);

  // We expect exactly one of {action_info, table_info} to be set.
  if (action_info != nullptr && table_info != nullptr) {
    return gutils::InternalErrorBuilder(GUTILS_LOC)
           << "Both action_info and table_info are nullptr.";
  }
  if (action_info == nullptr && table_info == nullptr) {
    return gutils::InternalErrorBuilder(GUTILS_LOC)
           << "Both action_info and table_info are not nullptr.";
  }

  switch (expr->expression_case()) {
    case ast::Expression::kBooleanConstant:
      expr->mutable_type()->mutable_boolean();
      return absl::OkStatus();

    case ast::Expression::kIntegerConstant:
      expr->mutable_type()->mutable_arbitrary_int();
      return absl::OkStatus();

    case ast::Expression::kKey: {
      // This case only applies to TableInfo.
      if (table_info == nullptr) {
        return StaticTypeError(constraint_source, expr->start_location(),
                               expr->end_location())
               << "unexpected key in action constraint";
      }
      const std::string_view key = expr->key();
      const auto& key_info = table_info->keys_by_name.find(key);
      if (key_info == table_info->keys_by_name.end())
        return StaticTypeError(table_info->constraint_source,
                               expr->start_location(), expr->end_location())
               << "unknown key " << key;
      *expr->mutable_type() = key_info->second.type;
      if (expr->type().type_case() == Type::kUnknown ||
          expr->type().type_case() == Type::kUnsupported) {
        return StaticTypeError(table_info->constraint_source,
                               expr->start_location(), expr->end_location())
               << "key " << key << " has illegal type "
               << TypeName(expr->type());
      }
      return absl::OkStatus();
    }

    case ast::Expression::kActionParameter: {
      // This case only applies to ActionInfo.
      if (action_info == nullptr) {
        return StaticTypeError(constraint_source, expr->start_location(),
                               expr->end_location())
               << "unexpected action parameter in table constraint";
      }
      const std::string_view param = expr->action_parameter();
      const auto& param_info = action_info->params_by_name.find(param);
      if (param_info == action_info->params_by_name.end())
        return StaticTypeError(action_info->constraint_source,
                               expr->start_location(), expr->end_location())
               << "unknown action parameter " << param;
      *expr->mutable_type() = param_info->second.type;
      if (expr->type().type_case() == Type::kUnknown ||
          expr->type().type_case() == Type::kUnsupported) {
        return StaticTypeError(action_info->constraint_source,
                               expr->start_location(), expr->end_location())
               << "action parameter " << param << " has illegal type "
               << TypeName(expr->type());
      }
      return absl::OkStatus();
    }

    case ast::Expression::kBooleanNegation: {
      Expression* sub_expr = expr->mutable_boolean_negation();
      RETURN_IF_ERROR(InferAndCheckTypes(sub_expr, action_info, table_info));
      if (!sub_expr->type().has_boolean()) {
        return StaticTypeError(constraint_source, sub_expr->start_location(),
                               sub_expr->end_location())
               << "expected type bool, got " << TypeName(sub_expr->type());
      }
      expr->mutable_type()->mutable_boolean();
      return absl::OkStatus();
    }

    case ast::Expression::kArithmeticNegation: {
      Expression* sub_expr = expr->mutable_arithmetic_negation();
      RETURN_IF_ERROR(InferAndCheckTypes(sub_expr, action_info, table_info));
      if (!sub_expr->type().has_arbitrary_int()) {
        return StaticTypeError(constraint_source, sub_expr->start_location(),
                               sub_expr->end_location())
               << "expected type int, got " << TypeName(sub_expr->type());
      }
      expr->mutable_type()->mutable_arbitrary_int();
      return absl::OkStatus();
    }

    case ast::Expression::kTypeCast: {
      // Type check the inner expression first
      Expression* inner_expr = expr->mutable_type_cast();
      RETURN_IF_ERROR(InferAndCheckTypes(inner_expr, action_info, table_info));

      const Type& target_type = expr->type();
      const Type& inner_type = inner_expr->type();

      // Validate the cast is exactly one level in the castability order
      if (!OneLevelAboveInCastabilityOrder(target_type, inner_type)) {
        return StaticTypeError(constraint_source, expr->start_location(),
                               expr->end_location())
               << "invalid type cast from " << TypeName(inner_type) << " to "
               << TypeName(target_type)
               << " - must be a single-step cast in the type hierarchy";
      }

      return absl::OkStatus();
    }
    case Expression::kBinaryExpression: {
      BinaryExpression* bin_expr = expr->mutable_binary_expression();
      Expression* left = bin_expr->mutable_left();
      Expression* right = bin_expr->mutable_right();
      RETURN_IF_ERROR(InferAndCheckTypes(left, action_info, table_info));
      RETURN_IF_ERROR(InferAndCheckTypes(right, action_info, table_info));
      switch (bin_expr->binop()) {
        case ast::BinaryOperator::AND:
        case ast::BinaryOperator::OR:
        case ast::BinaryOperator::IMPLIES: {
          for (auto subexpr : {left, right}) {
            if (!subexpr->type().has_boolean()) {
              return StaticTypeError(constraint_source,
                                     subexpr->start_location(),
                                     subexpr->end_location())
                     << "expected type bool, got " << TypeName(subexpr->type());
            }
          }
          expr->mutable_type()->mutable_boolean();
          return absl::OkStatus();
        }
        case ast::BinaryOperator::GT:
        case ast::BinaryOperator::GE:
        case ast::BinaryOperator::LT:
        case ast::BinaryOperator::LE:
        case ast::BinaryOperator::EQ:
        case ast::BinaryOperator::NE: {
          ASSIGN_OR_RETURN(Type type, Unify(left, right, constraint_source));
          // Unordered types only support == and !=.
          if (bin_expr->binop() != ast::BinaryOperator::EQ &&
              bin_expr->binop() != ast::BinaryOperator::NE &&
              !TypeHasOrdering(type)) {
            return StaticTypeError(constraint_source, expr->start_location(),
                                   expr->end_location())
                   << "operand type " << type
                   << " does not support ordered comparison";
          }
          expr->mutable_type()->mutable_boolean();
          return absl::OkStatus();
        }
        default:
          return gutils::InternalErrorBuilder(GUTILS_LOC)
                 << "unknown binary operator "
                 << ast::BinaryOperator_Name(bin_expr->binop());
      }
    }

    case ast::Expression::kFieldAccess: {
      Expression* composite_expr = expr->mutable_field_access()->mutable_expr();
      const std::string& field = expr->mutable_field_access()->field();
      RETURN_IF_ERROR(
          InferAndCheckTypes(composite_expr, action_info, table_info));
      absl::optional<Type> field_type =
          FieldTypeOfCompositeType(composite_expr->type(), field);
      if (!field_type.has_value()) {
        return StaticTypeError(constraint_source, expr->start_location(),
                               expr->end_location())
               << "expression of type " << composite_expr->type()
               << " has no field '" << field << "'";
      }
      *expr->mutable_type() = field_type.value();
      return absl::OkStatus();
    }

    case ast::Expression::kAttributeAccess: {
      const std::string& attribute_name =
          expr->attribute_access().attribute_name();
      const auto attribute_info = GetAttributeInfo(attribute_name);
      if (attribute_info == std::nullopt) {
        return StaticTypeError(constraint_source, expr->start_location(),
                               expr->end_location())
               << "unknown attribute '" << attribute_name << "'";
      }
      Type& expr_type = *expr->mutable_type();
      expr_type = attribute_info->type;
      if (expr_type.type_case() == Type::kUnknown ||
          expr_type.type_case() == Type::kUnsupported) {
        // Since we hardcode the type of attribute in the source code, this line
        // should never be reached.
        return InternalError(constraint_source, expr->start_location(),
                             expr->end_location())
               << "attribute '" << attribute_name << "' has illegal type "
               << TypeName(expr_type);
      }
      return absl::OkStatus();
    }

    case ast::Expression::EXPRESSION_NOT_SET:
      break;
  }
  return StaticTypeError(constraint_source, expr->start_location(),
                         expr->end_location())
         << "unexpected expression: " << expr->DebugString();
}  // namespace

absl::Status InferAndCheckTypes(Expression* expr, const TableInfo& table_info) {
  return InferAndCheckTypes(expr, /*action_info=*/nullptr, &table_info);
}

absl::Status InferAndCheckTypes(Expression* expr,
                                const ActionInfo& action_info) {
  return InferAndCheckTypes(expr, &action_info, /*table_info=*/nullptr);
}
}  // namespace p4_constraints
