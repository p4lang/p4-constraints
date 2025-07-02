// Copyright 2019 The MediaPipe Authors.
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

#ifndef THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_RET_CHECK_H_
#define THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_RET_CHECK_H_

#include "absl/base/optimization.h"
#include "absl/status/status.h"
#include "gutil/status.h"
#include "p4_constraints/source_location.h"

// Returns a StatusBuilder that corresponds to a `RET_CHECK` failure.
gutil::StatusBuilder RetCheckFailSlowPath(
    p4_constraints::SourceLocation location);

// Returns a StatusBuilder that corresponds to a `RET_CHECK` failure.
gutil::StatusBuilder RetCheckFailSlowPath(
    p4_constraints::SourceLocation location, const char* condition);

// Returns a StatusBuilder that corresponds to a `RET_CHECK` failure.
gutil::StatusBuilder RetCheckFailSlowPath(
    p4_constraints::SourceLocation location, const char* condition,
    const ::absl::Status& status);

inline gutil::StatusBuilder RetCheckImpl(
    const absl::Status& status, const char* condition,
    p4_constraints::SourceLocation location) {
  if (ABSL_PREDICT_TRUE(status.ok()))
    return gutil::StatusBuilder(absl::StatusCode::kOk);
  return RetCheckFailSlowPath(location, condition, status);
}

#define RET_CHECK(cond)               \
  while (ABSL_PREDICT_FALSE(!(cond))) \
  return RetCheckFailSlowPath(p4_constraints::SourceLocation::current(), #cond)

#define RET_CHECK_OK(status)                      \
  RETURN_IF_ERROR(RetCheckImpl((status), #status, \
                               p4_constraints::SourceLocation::current()))

#define RET_CHECK_FAIL() \
  return RetCheckFailSlowPath(p4_constraints::SourceLocation::current())

#define RET_CHECK_OP(name, op, lhs, rhs) RET_CHECK((lhs)op(rhs))

#define RET_CHECK_EQ(lhs, rhs) RET_CHECK_OP(EQ, ==, lhs, rhs)
#define RET_CHECK_NE(lhs, rhs) RET_CHECK_OP(NE, !=, lhs, rhs)
#define RET_CHECK_LE(lhs, rhs) RET_CHECK_OP(LE, <=, lhs, rhs)
#define RET_CHECK_LT(lhs, rhs) RET_CHECK_OP(LT, <, lhs, rhs)
#define RET_CHECK_GE(lhs, rhs) RET_CHECK_OP(GE, >=, lhs, rhs)
#define RET_CHECK_GT(lhs, rhs) RET_CHECK_OP(GT, >, lhs, rhs)

#endif  // THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_RET_CHECK_H_
