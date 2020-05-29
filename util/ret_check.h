// Copyright 2019 The MediaPipe Authors.
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

#ifndef MEDIAPIPE_DEPS_RET_CHECK_H_
#define MEDIAPIPE_DEPS_RET_CHECK_H_

#include "absl/base/optimization.h"
#include "util/status_builder.h"
#include "util/status_macros.h"

namespace util {
// Returns a StatusBuilder that corresponds to a `RET_CHECK` failure.
::util::StatusBuilder RetCheckFailSlowPath(::util::SourceLocation location);

// Returns a StatusBuilder that corresponds to a `RET_CHECK` failure.
::util::StatusBuilder RetCheckFailSlowPath(::util::SourceLocation location,
                                           const char* condition);

// Returns a StatusBuilder that corresponds to a `RET_CHECK` failure.
::util::StatusBuilder RetCheckFailSlowPath(::util::SourceLocation location,
                                           const char* condition,
                                           const ::absl::Status& status);

inline StatusBuilder RetCheckImpl(const ::absl::Status& status,
                                  const char* condition,
                                  ::util::SourceLocation location) {
  if (ABSL_PREDICT_TRUE(status.ok()))
    return ::util::StatusBuilder(absl::OkStatus(), location);
  return RetCheckFailSlowPath(location, condition, status);
}

}  // namespace util

#define RET_CHECK(cond)               \
  while (ABSL_PREDICT_FALSE(!(cond))) \
  return ::util::RetCheckFailSlowPath(UTIL_LOC, #cond)

#define RET_CHECK_OK(status) \
  RETURN_IF_ERROR(::util::RetCheckImpl((status), #status, UTIL_LOC))

#define RET_CHECK_FAIL() return ::util::RetCheckFailSlowPath(UTIL_LOC)

#define MEDIAPIPE_INTERNAL_RET_CHECK_OP(name, op, lhs, rhs) \
  RET_CHECK((lhs)op(rhs))

#define RET_CHECK_EQ(lhs, rhs) MEDIAPIPE_INTERNAL_RET_CHECK_OP(EQ, ==, lhs, rhs)
#define RET_CHECK_NE(lhs, rhs) MEDIAPIPE_INTERNAL_RET_CHECK_OP(NE, !=, lhs, rhs)
#define RET_CHECK_LE(lhs, rhs) MEDIAPIPE_INTERNAL_RET_CHECK_OP(LE, <=, lhs, rhs)
#define RET_CHECK_LT(lhs, rhs) MEDIAPIPE_INTERNAL_RET_CHECK_OP(LT, <, lhs, rhs)
#define RET_CHECK_GE(lhs, rhs) MEDIAPIPE_INTERNAL_RET_CHECK_OP(GE, >=, lhs, rhs)
#define RET_CHECK_GT(lhs, rhs) MEDIAPIPE_INTERNAL_RET_CHECK_OP(GT, >, lhs, rhs)

#endif  // MEDIAPIPE_DEPS_RET_CHECK_H_
