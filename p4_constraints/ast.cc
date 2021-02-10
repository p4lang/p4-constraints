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

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "glog/logging.h"
#include "net/google::protobuf/util/public/message_differencer.h"
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
    default:
      return "???";
  }
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
    default:
      return {};
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
    default:
      return false;
  }
}

Type TypeCaseToType(Type::TypeCase type_case) {
  Type type;
  switch (type_case) {
    case Type::kUnknown:
      type.mutable_unknown();
      break;
    case Type::kUnsupported:
      type.mutable_unsupported();
      break;
    case Type::kBoolean:
      type.mutable_boolean();
      break;
    case Type::kArbitraryInt:
      type.mutable_arbitrary_int();
      break;
    case Type::kFixedUnsigned:
      type.mutable_fixed_unsigned();
      break;
    case Type::kExact:
      type.mutable_exact();
      break;
    case Type::kTernary:
      type.mutable_ternary();
      break;
    case Type::kLpm:
      type.mutable_lpm();
      break;
    case Type::kRange:
      type.mutable_range();
      break;
    default:
      LOG(DFATAL) << "unknown type case: " << type_case;
  }
  DCHECK_EQ(type.type_case(), type_case);
  return type;
}

}  // namespace ast
}  // namespace p4_constraints
