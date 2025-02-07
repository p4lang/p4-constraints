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

#include "p4_constraints/frontend/token.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <type_traits>

namespace p4_constraints {

using ::testing::Eq;
using ::testing::Optional;

// Tries to catch cases where `Token::kAllKinds` does not include all token
// kinds. Unfortunately, we cannot catch all such cases due to C++ limitations.
TEST(TokenTest, AllKindsHasCorrectSize) {
  // We maintain the invariant that UNEXPECTED_CHAR is the last (i.e., maximum)
  // token kind in the enum Token::Kind.
  for (Token::Kind kind : Token::kAllKinds) {
    ASSERT_GE(kind, 0) << "Token::Kind must be nonnegative";
    ASSERT_LE(kind, Token::UNEXPECTED_CHAR)
        << "UNEXPECTED_CHAR should be last (i.e., maximum) Token::Kind in enum";
  }
  const int kNumberOfKinds = std::extent<decltype(Token::kAllKinds)>::value;
  EXPECT_EQ(kNumberOfKinds, Token::UNEXPECTED_CHAR + 1);
}

TEST(TokenTest, KindToKeyword_KeywordToKind_Rountrip) {
  for (Token::Kind kind : Token::kAllKinds) {
    EXPECT_THAT(Token::KeywordToKind(Token::KindToKeyword(kind)),
                Optional(Eq(kind)));
  }
}

}  // namespace p4_constraints
