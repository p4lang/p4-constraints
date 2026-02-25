// Copyright 2026 The P4-Constraints Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef P4_CONSTRAINTS_BIG_INT_H_
#define P4_CONSTRAINTS_BIG_INT_H_

#include <boost/multiprecision/cpp_int.hpp>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace p4_constraints {

using BigInt = boost::multiprecision::cpp_int;

std::string BigIntToString(const BigInt& value);

absl::StatusOr<BigInt> ParseBigInt(absl::string_view text, int base = 10);

BigInt ParseBigEndianBytes(absl::string_view bytes);

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_BIG_INT_H_
