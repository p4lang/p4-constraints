// Copyright 2026 The P4-Constraints Authors
// SPDX-License-Identifier: Apache-2.0

#include "p4_constraints/big_int.h"

#include "gutil/status.h"

namespace p4_constraints {
namespace {

absl::StatusOr<int> DigitValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return gutil::InvalidArgumentErrorBuilder() << "invalid digit '" << c << "'";
}

}  // namespace

std::string BigIntToString(const BigInt& value) { return value.str(); }

absl::StatusOr<BigInt> ParseBigInt(absl::string_view text, int base) {
  if (text.empty()) {
    return gutil::InvalidArgumentErrorBuilder() << "cannot parse empty integer";
  }
  if (base != 2 && base != 8 && base != 10 && base != 16) {
    return gutil::InvalidArgumentErrorBuilder()
           << "unsupported integer base " << base;
  }

  bool negative = false;
  size_t pos = 0;
  if (text.front() == '-') {
    negative = true;
    pos = 1;
  }
  if (pos == text.size()) {
    return gutil::InvalidArgumentErrorBuilder()
           << "cannot parse integer '" << text << "'";
  }

  BigInt result = 0;
  for (; pos < text.size(); ++pos) {
    ASSIGN_OR_RETURN(int digit, DigitValue(text[pos]));
    if (digit >= base) {
      return gutil::InvalidArgumentErrorBuilder()
             << "digit '" << text[pos] << "' out of range for base " << base;
    }
    result *= base;
    result += digit;
  }

  return negative ? -result : result;
}

BigInt ParseBigEndianBytes(absl::string_view bytes) {
  BigInt result = 0;
  for (unsigned char byte : bytes) {
    result <<= 8;
    result += byte;
  }
  return result;
}

}  // namespace p4_constraints
