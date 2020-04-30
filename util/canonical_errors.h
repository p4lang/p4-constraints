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

#ifndef MEDIAPIPE_DEPS_CANONICAL_ERRORS_H_
#define MEDIAPIPE_DEPS_CANONICAL_ERRORS_H_

#include "util/status.h"

namespace util {

// Each of the functions below creates a canonical error with the given
// message. The error code of the returned status object matches the name of
// the function.
inline ::util::Status AlreadyExistsError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kAlreadyExists, message);
}

inline ::util::Status CancelledError() {
  return ::util::Status(::util::StatusCode::kCancelled, "");
}

inline ::util::Status CancelledError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kCancelled, message);
}

inline ::util::Status InternalError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kInternal, message);
}

inline ::util::Status InvalidArgumentError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kInvalidArgument,
                             message);
}

inline ::util::Status FailedPreconditionError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kFailedPrecondition,
                             message);
}

inline ::util::Status NotFoundError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kNotFound, message);
}

inline ::util::Status OutOfRangeError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kOutOfRange, message);
}

inline ::util::Status PermissionDeniedError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kPermissionDenied,
                             message);
}

inline ::util::Status UnimplementedError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kUnimplemented, message);
}

inline ::util::Status UnknownError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kUnknown, message);
}

inline ::util::Status UnavailableError(absl::string_view message) {
  return ::util::Status(::util::StatusCode::kUnavailable, message);
}

inline bool IsCancelled(const ::util::Status& status) {
  return status.code() == ::util::StatusCode::kCancelled;
}

inline bool IsNotFound(const ::util::Status& status) {
  return status.code() == ::util::StatusCode::kNotFound;
}

}  // namespace util

#endif  // MEDIAPIPE_DEPS_CANONICAL_ERRORS_H_
