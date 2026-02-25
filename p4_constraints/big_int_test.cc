// Copyright 2026 The P4-Constraints Authors
// SPDX-License-Identifier: Apache-2.0

#include "p4_constraints/big_int.h"

#include <gtest/gtest.h>

#include "gutil/status_matchers.h"

namespace p4_constraints {
namespace {

using ::gutil::IsOkAndHolds;

TEST(BigIntTest, ParseBigIntParsesDecimalAndHex) {
  EXPECT_THAT(ParseBigInt("42"), IsOkAndHolds(BigInt(42)));
  EXPECT_THAT(ParseBigInt("-17"), IsOkAndHolds(BigInt(-17)));
  EXPECT_THAT(ParseBigInt("ff", 16), IsOkAndHolds(BigInt(255)));
}

TEST(BigIntTest, ParseBigIntRejectsInvalidDigit) {
  EXPECT_FALSE(ParseBigInt("2", 2).ok());
}

TEST(BigIntTest, ParseBigEndianBytesParsesBytestring) {
  EXPECT_EQ(ParseBigEndianBytes(std::string("\x12\x34", 2)), BigInt(0x1234));
}

TEST(BigIntTest, BigIntToStringFormatsValue) {
  EXPECT_EQ(BigIntToString(BigInt("12345678901234567890")),
            "12345678901234567890");
}

}  // namespace
}  // namespace p4_constraints
