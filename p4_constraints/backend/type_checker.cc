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

#include "p4_constraints/backend/type_checker.h"

#include <string>
#include <tuple>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "gutils/status.h"
#include "gutils/status_builder.h"
#include "gutils/status_macros.h"
#include "p4_constraints/ast.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/quote.h"

namespace p4_constraints {

namespace {

using ::p4_constraints::ast::BinaryExpression;
using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::SourceLocation;
using ::p4_constraints::ast::Type;

// -- Error handling -----------------------------------------------------------

gutils::StatusBuilder TypeError(const ConstraintSource& source,
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
                           const TableInfo& table_info) {
  const absl::optional<Type> least_upper_bound =
      LeastUpperBound(left->type(), right->type());
  if (!least_upper_bound.has_value()) {
    return TypeError(table_info.constraint_source, left->start_location(),
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
    new absl::flat_hash_map<const CompositeTypeAndField, const Type::TypeCase>{
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

absl::Status InferAndCheckTypes(Expression* expr, const TableInfo& table_info) {
  switch (expr->expression_case()) {
    case Expression::kBooleanConstant:
      expr->mutable_type()->mutable_boolean();
      return absl::OkStatus();

    case Expression::kIntegerConstant:
      expr->mutable_type()->mutable_arbitrary_int();
      return absl::OkStatus();

    case Expression::kKey: {
      const std::string& key = expr->key();
      const auto& key_info = table_info.keys_by_name.find(key);
      if (key_info == table_info.keys_by_name.end())
        return TypeError(table_info.constraint_source, expr->start_location(),
                         expr->end_location())
               << "unknown key " << key;
      *expr->mutable_type() = key_info->second.type;
      if (expr->type().type_case() == Type::kUnknown ||
          expr->type().type_case() == Type::kUnsupported) {
        return TypeError(table_info.constraint_source, expr->start_location(),
                         expr->end_location())
               << "key " << key << " has illegal type "
               << TypeName(expr->type());
      }
      return absl::OkStatus();
    }

    case Expression::kMetadataAccess: {
      const std::string& metadata_name =
          expr->metadata_access().metadata_name();
      const auto metadata_info = GetMetadataInfo(metadata_name);
      if (metadata_info == std::nullopt) {
        return TypeError(table_info.constraint_source, expr->start_location(),
                         expr->end_location())
               << "unknown metadata '" << metadata_name << "'";
      }
      Type& expr_type = *expr->mutable_type();
      expr_type = metadata_info->type;
      if (expr_type.type_case() == Type::kUnknown ||
          expr_type.type_case() == Type::kUnsupported) {
        // Since we hardcode the type of metadata in the source code, this line
        // should never be reached.
        return InternalError(table_info.constraint_source,
                             expr->start_location(), expr->end_location())
               << "metadata '" << metadata_name << "' has illegal type "
               << TypeName(expr_type);
      }
      return absl::OkStatus();
    }

    case Expression::kBooleanNegation: {
      Expression* sub_expr = expr->mutable_boolean_negation();
      RETURN_IF_ERROR(InferAndCheckTypes(sub_expr, table_info));
      if (!sub_expr->type().has_boolean()) {
        return TypeError(table_info.constraint_source,
                         sub_expr->start_location(), sub_expr->end_location())
               << "expected type bool, got " << TypeName(sub_expr->type());
      }
      expr->mutable_type()->mutable_boolean();
      return absl::OkStatus();
    }

    case Expression::kArithmeticNegation: {
      Expression* sub_expr = expr->mutable_arithmetic_negation();
      RETURN_IF_ERROR(InferAndCheckTypes(sub_expr, table_info));
      if (!sub_expr->type().has_arbitrary_int()) {
        return TypeError(table_info.constraint_source,
                         sub_expr->start_location(), sub_expr->end_location())
               << "expected type int, got " << TypeName(sub_expr->type());
      }
      expr->mutable_type()->mutable_arbitrary_int();
      return absl::OkStatus();
    }

    case Expression::kBinaryExpression: {
      BinaryExpression* bin_expr = expr->mutable_binary_expression();
      Expression* left = bin_expr->mutable_left();
      Expression* right = bin_expr->mutable_right();
      RETURN_IF_ERROR(InferAndCheckTypes(left, table_info));
      RETURN_IF_ERROR(InferAndCheckTypes(right, table_info));
      switch (bin_expr->binop()) {
        case ast::BinaryOperator::AND:
        case ast::BinaryOperator::OR:
        case ast::BinaryOperator::IMPLIES: {
          for (auto subexpr : {left, right}) {
            if (!subexpr->type().has_boolean()) {
              return TypeError(table_info.constraint_source,
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
          ASSIGN_OR_RETURN(Type type, Unify(left, right, table_info));
          // Unordered types only support == and !=.
          if (bin_expr->binop() != ast::BinaryOperator::EQ &&
              bin_expr->binop() != ast::BinaryOperator::NE &&
              !TypeHasOrdering(type)) {
            return TypeError(table_info.constraint_source,
                             expr->start_location(), expr->end_location())
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

    case Expression::kTypeCast:
      return TypeError(table_info.constraint_source, expr->start_location(),
                       expr->end_location())
             << "type casts should only be inserted by the type checker";

    case Expression::kFieldAccess: {
      Expression* composite_expr = expr->mutable_field_access()->mutable_expr();
      const std::string& field = expr->mutable_field_access()->field();
      RETURN_IF_ERROR(InferAndCheckTypes(composite_expr, table_info));
      absl::optional<Type> field_type =
          FieldTypeOfCompositeType(composite_expr->type(), field);
      if (!field_type.has_value()) {
        return TypeError(table_info.constraint_source, expr->start_location(),
                         expr->end_location())
               << "expression of type " << composite_expr->type()
               << " has no field '" << field << "'";
      }
      *expr->mutable_type() = field_type.value();
      return absl::OkStatus();
    }

    case Expression::EXPRESSION_NOT_SET:
      break;
  }
  return TypeError(table_info.constraint_source, expr->start_location(),
                   expr->end_location())
         << "unexpected expression: " << expr->DebugString();
}

}  // namespace p4_constraints
