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

#include "p4_constraints/frontend/ast_constructors.h"

#include <arpa/inet.h>
#include <gmpxx.h>

#include <bitset>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "gutils/ret_check.h"
#include "gutils/status_builder.h"
#include "gutils/status_macros.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/frontend/constraint_kind.h"
#include "p4_constraints/frontend/token.h"

namespace p4_constraints {
namespace ast {

namespace {

// -- Auxiliary conversion functions -------------------------------------------

// Converts token.h to ast.proto representation.
absl::StatusOr<ast::BinaryOperator> ConvertBinaryOperator(Token::Kind binop) {
  switch (binop) {
    case Token::AND:
    case Token::SEMICOLON:
      return ast::AND;
    case Token::OR:
      return ast::OR;
    case Token::IMPLIES:
      return ast::IMPLIES;
    case Token::EQ:
      return ast::EQ;
    case Token::NE:
      return ast::NE;
    case Token::GT:
      return ast::GT;
    case Token::GE:
      return ast::GE;
    case Token::LT:
      return ast::LT;
    case Token::LE:
      return ast::LE;
    default:
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "expected binary operator, got " << binop;
  }
}

absl::StatusOr<std::string> ConvertNumeral(const Token& numeral_token) {
  mpz_class numeral;
  switch (numeral_token.kind) {
    case Token::BINARY:
      RET_CHECK_EQ(numeral.set_str(numeral_token.text, 2), 0)
          << "invalid binary string \"" << numeral_token.text << "\".\n";
      return numeral.get_str(10);
    case Token::OCTARY:
      RET_CHECK_EQ(numeral.set_str(numeral_token.text, 8), 0)
          << "invalid octary string \"" << numeral_token.text << "\".\n";
      return numeral.get_str(10);
    case Token::DECIMAL:
      RET_CHECK_EQ(numeral.set_str(numeral_token.text, 10), 0)
          << "invalid decimal string \"" << numeral_token.text << "\".\n";
      return numeral.get_str(10);
    case Token::HEXADEC:
      RET_CHECK_EQ(numeral.set_str(numeral_token.text, 16), 0)
          << "invalid hexadecimal string \"" << numeral_token.text << "\".\n";
      return numeral.get_str(10);
    default:
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << "expected numeral, got " << numeral_token.kind;
  }
}

absl::StatusOr<uint8_t> Base10StringToByte(
    const std::string_view& base10_string) {
  uint8_t byte;
  if (base10_string.empty() || base10_string.size() > 3) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << absl::StreamFormat(
                  "Invalid base10 string length: '%d', expected 0 < string "
                  "length < 3.",
                  base10_string.size());
  }
  int buffer = 0;
  for (char c : base10_string) {
    if (c > '9' || c < '0') {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << absl::StreamFormat(
                    "Invalid character in base-10 string: '%c' in string '%s'",
                    c, base10_string);
    }
    buffer = buffer * 10 + (c - '0');
  }
  if (buffer > 255) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << absl::StreamFormat(
                  "Invalid base10 string. Buffer size of '%d' exceeded 255",
                  buffer);
  }
  memcpy(&byte, &buffer, 1);
  return byte;
}

absl::StatusOr<uint8_t> Base16StringToByte(absl::string_view& base16_string) {
  uint8_t byte;
  if (base16_string.empty() || base16_string.size() > 2) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << absl::StreamFormat(
                  "Invalid base16 string length: '%d', expected 0 < string "
                  "length <= 2.",
                  base16_string.size());
  }
  int buffer = 0;
  for (char c : base16_string) {
    if (!absl::ascii_isxdigit(c)) {
      return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
             << absl::StreamFormat(
                    "Invalid character in base16 string: '%c' in string '%s'",
                    c, base16_string);
    }
    int value =
        (c >= 'A') ? (c >= 'a') ? (c - 'a' + 10) : (c - 'A' + 10) : (c - '0');
    buffer = buffer * 16 + value;
  }
  memcpy(&byte, &buffer, 1);
  return byte;
}

absl::StatusOr<std::string> Ipv4StringToByteString(
    const absl::string_view& ipv4_address) {
  std::vector<std::string_view> bytes = absl::StrSplit(ipv4_address, '.');
  if (bytes.size() != 4) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << absl::StreamFormat(
                  "Invalid length for an IPv4 address: '%s'. Expected IPv4 "
                  "address to be 4 bytes.",
                  ipv4_address);
  }

  std::bitset<32> bits;
  for (absl::string_view& byte_string : bytes) {
    ASSIGN_OR_RETURN(uint8_t byte, Base10StringToByte(byte_string));
    bits <<= 8;
    bits |= byte;
  }
  return bits.to_string();
}

template <std::size_t num_bits>
std::bitset<num_bits> AnyByteStringToBitset(
    const absl::string_view& byte_string) {
  std::bitset<num_bits> bits;
  for (char c : byte_string) {
    uint8_t byte = 0;
    memcpy(&byte, &c, 1);
    bits <<= 8;
    bits |= byte;
  }
  return bits;
}

absl::StatusOr<std::string> Ipv6StringToByteString(
    const absl::string_view& ipv6_address) {
  std::string bytes = std::string(128 / 8, '\x0');
  if (inet_pton(10, ipv6_address.data(), bytes.data()) == 1) {
    auto ip = AnyByteStringToBitset<128>(bytes);
    return ip.to_string();
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << absl::StreamFormat("Invalid Ipv6 address: %s", ipv6_address);
}

absl::StatusOr<std::string> MacStringToByteString(
    const absl::string_view& mac_address) {
  std::vector<std::string> bytes = absl::StrSplit(mac_address, ':');
  if (bytes.size() != 6) {
    return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
           << absl::StreamFormat(
                  "Invalid length for MAC address: '%s'. Expected MAC address"
                  " to be 6 bytes.",
                  mac_address);
  }

  std::bitset<48> bits;
  for (absl::string_view byte_string : bytes) {
    ASSIGN_OR_RETURN(uint8_t byte, Base16StringToByte(byte_string));
    bits <<= 8;
    bits |= byte;
  }
  return bits.to_string();
}

// -- Auxiliary base constructors ----------------------------------------------

ast::Expression LocatedExpression(const ast::SourceLocation& start_location,
                                  const ast::SourceLocation& end_location) {
  ast::Expression ast;
  *ast.mutable_start_location() = start_location;
  *ast.mutable_end_location() = end_location;
  return ast;
}

}  // namespace

// -- Public AST constructors --------------------------------------------------

absl::StatusOr<ast::Expression> MakeBooleanConstant(const Token& boolean) {
  RET_CHECK(boolean.kind == Token::TRUE || boolean.kind == Token::FALSE)
      << "expected boolean, got " << boolean.kind;
  ast::Expression ast =
      LocatedExpression(boolean.start_location, boolean.end_location);
  ast.set_boolean_constant(boolean.kind == Token::TRUE);
  return ast;
}

absl::StatusOr<ast::Expression> MakeIntegerConstant(const Token& numeral) {
  ASSIGN_OR_RETURN(std::string numeral_str, ConvertNumeral(numeral));
  ast::Expression ast =
      LocatedExpression(numeral.start_location, numeral.end_location);
  ast.set_integer_constant(numeral_str);
  return ast;
}

absl::StatusOr<ast::Expression> MakeNetworkAddressIntegerConstant(
    const absl::string_view& address_type,
    const absl::string_view& address_string,
    const ast::SourceLocation& start_location,
    const ast::SourceLocation& end_location) {
  std::string numeral_str;
  if (address_type == "ipv4") {
    ASSIGN_OR_RETURN(std::string ipv4_bits,
                     Ipv4StringToByteString(address_string));
    ASSIGN_OR_RETURN(numeral_str,
                     ConvertNumeral(Token(Token::BINARY, ipv4_bits,
                                          start_location, end_location)));
  } else if (address_type == "ipv6") {
    ASSIGN_OR_RETURN(std::string ipv6_bytes,
                     Ipv6StringToByteString(address_string));
    ASSIGN_OR_RETURN(numeral_str,
                     ConvertNumeral(Token(Token::BINARY, ipv6_bytes,
                                          start_location, end_location)));
  } else if (address_type == "mac") {
    ASSIGN_OR_RETURN(std::string mac_bytes,
                     MacStringToByteString(address_string));
    ASSIGN_OR_RETURN(numeral_str,
                     ConvertNumeral(Token(Token::BINARY, mac_bytes,
                                          start_location, end_location)));
  } else {
    return absl::InvalidArgumentError("Invalid network identifier");
  }
  ast::Expression ast = LocatedExpression(start_location, end_location);
  ast.set_integer_constant(numeral_str);
  return ast;
}

absl::StatusOr<ast::Expression> MakeBooleanNegation(const Token& bang_token,
                                                    ast::Expression operand) {
  RET_CHECK_EQ(bang_token.kind, Token::BANG);
  ast::Expression ast =
      LocatedExpression(bang_token.start_location, operand.end_location());
  *ast.mutable_boolean_negation() = std::move(operand);
  return ast;
}

absl::StatusOr<ast::Expression> MakeArithmeticNegation(
    const Token& minus_token, ast::Expression operand) {
  RET_CHECK_EQ(minus_token.kind, Token::MINUS);
  ast::Expression ast =
      LocatedExpression(minus_token.start_location, operand.end_location());
  *ast.mutable_arithmetic_negation() = std::move(operand);
  return ast;
}

absl::StatusOr<ast::Expression> MakeVariable(absl::Span<const Token> tokens,
                                             ConstraintKind constraint_kind) {
  RET_CHECK_GT(tokens.size(), 0);
  ast::Expression ast = LocatedExpression(tokens.front().start_location,
                                          tokens.back().end_location);
  std::stringstream key_or_param{};
  for (int i = 0; i < tokens.size(); i++) {
    const Token& id = tokens[i];
    RET_CHECK_EQ(id.kind, Token::ID);
    switch (constraint_kind) {
      case ConstraintKind::kTableConstraint: {
        key_or_param << (i == 0 ? "" : ".") << id.text;
        break;
      }
      case ConstraintKind::kActionConstraint: {
        key_or_param << id.text;
        break;
      }
    }
  }
  switch (constraint_kind) {
    case ConstraintKind::kTableConstraint: {
      ast.set_key(key_or_param.str());
      return ast;
    }
    case ConstraintKind::kActionConstraint: {
      ast.set_action_parameter(key_or_param.str());
      return ast;
    }
  }
  return gutils::InvalidArgumentErrorBuilder(GUTILS_LOC)
         << "Unexpected value for ConstraintKind: "
         << static_cast<int>(constraint_kind);
}

absl::StatusOr<ast::Expression> MakeAttributeAccess(
    const Token& double_colon, const Token& attribute_name) {
  ast::Expression ast = LocatedExpression(double_colon.start_location,
                                          attribute_name.end_location);
  ast.mutable_attribute_access()->set_attribute_name(attribute_name.text);
  return ast;
}

absl::StatusOr<ast::Expression> MakeBinaryExpression(const Token& binop_token,
                                                     ast::Expression left,
                                                     ast::Expression right) {
  ast::Expression ast =
      LocatedExpression(left.start_location(), right.end_location());
  ast::BinaryExpression* binexpr = ast.mutable_binary_expression();

  ASSIGN_OR_RETURN(ast::BinaryOperator binop,
                   ConvertBinaryOperator(binop_token.kind));
  binexpr->set_binop(binop);
  *binexpr->mutable_left() = std::move(left);
  *binexpr->mutable_right() = std::move(right);
  return ast;
}

absl::StatusOr<ast::Expression> MakeFieldAccess(ast::Expression expr,
                                                const Token& field) {
  RET_CHECK_EQ(field.kind, Token::ID);
  ast::Expression ast =
      LocatedExpression(expr.start_location(), field.end_location);
  *ast.mutable_field_access()->mutable_expr() = std::move(expr);
  ast.mutable_field_access()->set_field(field.text);
  return ast;
}

}  // namespace ast
}  // namespace p4_constraints
