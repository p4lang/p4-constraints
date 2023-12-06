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

#include "p4_constraints/ast.h"

#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/log/log.h"
#include "absl/meta/type_traits.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/util/message_differencer.h"
#include "gutils/proto.h"
#include "gutils/status_builder.h"
#include "gutils/status_macros.h"
#include "p4_constraints/ast.pb.h"

namespace p4_constraints {
namespace ast {

// -- Source Locations ---------------------------------------------------------

bool operator==(const SourceLocation& left, const SourceLocation& right) {
  return left.line() == right.line() && left.column() == right.column() &&
         left.source_case() == right.source_case() &&
         left.file_path() == right.file_path() &&
         left.table_name() == right.table_name();
}

std::ostream& operator<<(std::ostream& os, const SourceLocation& location) {
  return os << absl::StripAsciiWhitespace(location.DebugString());
}

// -- Types --------------------------------------------------------------------

bool operator==(const Type& left, const Type& right) {
  return google::protobuf::util::MessageDifferencer::Equals(left, right);
}

std::string TypeName(const Type& type) {
  switch (type.type_case()) {
    case Type::kUnknown:
      return "unknown";
    case Type::kUnsupported:
      return type.unsupported().name();
    case Type::kBoolean:
      return "bool";
    case Type::kArbitraryInt:
      return "int";
    case Type::kFixedUnsigned:
      return absl::StrCat("bit<", type.fixed_unsigned().bitwidth(), ">");
    case Type::kExact:
      return absl::StrCat("exact<", type.exact().bitwidth(), ">");
    case Type::kTernary:
      return absl::StrCat("ternary<", type.ternary().bitwidth(), ">");
    case Type::kLpm:
      return absl::StrCat("bit<", type.lpm().bitwidth(), ">");
    case Type::kRange:
      return absl::StrCat("range<", type.range().bitwidth(), ">");
    case Type::kOptionalMatch:
      return absl::StrCat("optional<", type.optional_match().bitwidth(), ">");
    case Type::TYPE_NOT_SET:
      break;
  }
  LOG(ERROR) << "invalid type: " << type.DebugString();
  return "???";
}

std::ostream& operator<<(std::ostream& os, const Type& type) {
  return os << TypeName(type);
}

// True iff values of the given type support ordered comparison (<, <=, >, >=).
bool TypeHasOrdering(const Type& type) {
  switch (type.type_case()) {
    case Type::kArbitraryInt:
    case Type::kFixedUnsigned:
    case Type::kExact:
      return true;
    default:
      return false;
  }
}

absl::optional<int> TypeBitwidth(const Type& type) {
  switch (type.type_case()) {
    case Type::kFixedUnsigned:
      return type.fixed_unsigned().bitwidth();
    case Type::kExact:
      return type.exact().bitwidth();
    case Type::kTernary:
      return type.ternary().bitwidth();
    case Type::kLpm:
      return type.lpm().bitwidth();
    case Type::kRange:
      return type.range().bitwidth();
    case Type::kOptionalMatch:
      return type.optional_match().bitwidth();
    default:
      return absl::nullopt;
  }
}

absl::StatusOr<int> TypeBitwidthOrStatus(const Type& type) {
  std::optional<int> bitwidth = TypeBitwidth(type);
  if (bitwidth.has_value()) {
    return *bitwidth;
  } else {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "expected a type with bitwidth, but got: " << type;
  }
}

bool SetTypeBitwidth(Type* type, int bitwidth) {
  switch (type->type_case()) {
    case Type::kFixedUnsigned:
      type->mutable_fixed_unsigned()->set_bitwidth(bitwidth);
      return true;
    case Type::kExact:
      type->mutable_exact()->set_bitwidth(bitwidth);
      return true;
    case Type::kTernary:
      type->mutable_ternary()->set_bitwidth(bitwidth);
      return true;
    case Type::kLpm:
      type->mutable_lpm()->set_bitwidth(bitwidth);
      return true;
    case Type::kRange:
      type->mutable_range()->set_bitwidth(bitwidth);
      return true;
    case Type::kOptionalMatch:
      type->mutable_optional_match()->set_bitwidth(bitwidth);
      return true;
    default:
      return false;
  }
}

Type TypeCaseToType(Type::TypeCase type_case) {
  Type type;
  switch (type_case) {
    case Type::kUnknown:
      type.mutable_unknown();
      return type;
    case Type::kUnsupported:
      type.mutable_unsupported();
      return type;
    case Type::kBoolean:
      type.mutable_boolean();
      return type;
    case Type::kArbitraryInt:
      type.mutable_arbitrary_int();
      return type;
    case Type::kFixedUnsigned:
      type.mutable_fixed_unsigned();
      return type;
    case Type::kExact:
      type.mutable_exact();
      return type;
    case Type::kTernary:
      type.mutable_ternary();
      return type;
    case Type::kLpm:
      type.mutable_lpm();
      return type;
    case Type::kRange:
      type.mutable_range();
      return type;
    case Type::kOptionalMatch:
      type.mutable_optional_match();
      return type;
    case Type::TYPE_NOT_SET:
      break;
  }
  LOG(ERROR) << "invalid type case: " << type_case;
  return type;
}

// -- Utility ------------------------------------------------------------------

bool HaveSameSource(const SourceLocation& source_location_1,
                    const SourceLocation& source_location_2) {
  // Message Differencer ignores all fields except `source` oneof. This makes
  // proto equivalence = source equivalence.
  google::protobuf::util::MessageDifferencer differ;
  differ.IgnoreField(
      source_location_1.GetDescriptor()->FindFieldByName("line"));
  differ.IgnoreField(
      source_location_1.GetDescriptor()->FindFieldByName("column"));
  return gutils::ProtoEqual(source_location_1, source_location_2, differ);
}

// Populates `variable_set` with the variables used in `expr`.
void AddVariables(const ast::Expression& expr,
                  absl::flat_hash_set<std::string>& variable_set) {
  switch (expr.expression_case()) {
    case ast::Expression::kKey:
      variable_set.insert(expr.key());
      return;
    case ast::Expression::kActionParameter:
      variable_set.insert(expr.action_parameter());
      return;
    case ast::Expression::kBooleanNegation:
      AddVariables(expr.boolean_negation(), variable_set);
      return;
    case ast::Expression::kArithmeticNegation:
      AddVariables(expr.arithmetic_negation(), variable_set);
      return;
    case ast::Expression::kTypeCast:
      AddVariables(expr.type_cast(), variable_set);
      return;
    case ast::Expression::kBinaryExpression:
      AddVariables(expr.binary_expression().left(), variable_set);
      AddVariables(expr.binary_expression().right(), variable_set);
      return;
    case ast::Expression::kFieldAccess:
      AddVariables(expr.field_access().expr(), variable_set);
      return;
    // Currently priority is the only metadata and that is not a key.
    case ast::Expression::kAttributeAccess:
      return;
    case ast::Expression::kIntegerConstant:
      return;
    case ast::Expression::kBooleanConstant:
      return;
    case ast::Expression::EXPRESSION_NOT_SET:
      return;
  }
}

absl::flat_hash_set<std::string> GetVariables(const ast::Expression& expr) {
  absl::flat_hash_set<std::string> field_set;
  AddVariables(expr, field_set);
  return field_set;
}

// Computes AST Size. If provided, `size_cache` stores results from expressions
// to avoid recomputation later.
absl::StatusOr<int> Size(const ast::Expression& ast, SizeCache* size_cache) {
  if (size_cache != nullptr) {
    auto cache_result = size_cache->find(&ast);
    if (cache_result != size_cache->end()) return cache_result->second;
  }

  int result = 0;
  switch (ast.expression_case()) {
    case Expression::kBooleanConstant:
    case Expression::kIntegerConstant:
    case Expression::kKey:
    case Expression::kArithmeticNegation:
    case Expression::kTypeCast:
    case Expression::kFieldAccess:
    case Expression::kAttributeAccess:
      // Uses an early return for these cases because they all resolve to a
      // single value (not an expression) and are therefore treated as having
      // size 1. Result is not cached because it provides no benefit beyond
      // early return.
      return 1;
    case Expression::kBinaryExpression: {
      ASSIGN_OR_RETURN(int left_size,
                       Size(ast.binary_expression().left(), size_cache));
      ASSIGN_OR_RETURN(int right_size,
                       Size(ast.binary_expression().right(), size_cache));
      result = 1 + left_size + right_size;
      break;
    }
    case Expression::kBooleanNegation: {
      ASSIGN_OR_RETURN(int size, Size(ast.boolean_negation(), size_cache));
      result = 1 + size;
      break;
    }
    default:
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "invalid expression: " << ast.DebugString();
  }

  if (size_cache != nullptr) size_cache->insert({&ast, result});
  return result;
}

}  // namespace ast
}  // namespace p4_constraints
