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

#ifndef MEDIAPIPE_DEPS_STATUS_BUILDER_H_
#define MEDIAPIPE_DEPS_STATUS_BUILDER_H_

#include "absl/base/attributes.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "util/source_location.h"
#include "util/status.h"

namespace util {

class ABSL_MUST_USE_RESULT StatusBuilder {
 public:
  StatusBuilder(const StatusBuilder& sb);
  StatusBuilder& operator=(const StatusBuilder& sb);
  // Creates a `StatusBuilder` based on an original status.  If logging is
  // enabled, it will use `location` as the location from which the log message
  // occurs.  A typical user will call this with `UTIL_LOC`.
  StatusBuilder(const ::util::Status& original_status,
                ::util::source_location location)
      : status_(original_status),
        line_(location.line()),
        file_(location.file_name()),
        stream_(new std::ostringstream) {}

  StatusBuilder(::util::Status&& original_status,
                ::util::source_location location)
      : status_(std::move(original_status)),
        line_(location.line()),
        file_(location.file_name()),
        stream_(new std::ostringstream) {}

  // Creates a `StatusBuilder` from a util status code.  If logging is
  // enabled, it will use `location` as the location from which the log message
  // occurs.  A typical user will call this with `UTIL_LOC`.
  StatusBuilder(::util::StatusCode code,
                ::util::source_location location)
      : status_(code, ""),
        line_(location.line()),
        file_(location.file_name()),
        stream_(new std::ostringstream) {}

  StatusBuilder(const ::util::Status& original_status, const char* file,
                int line)
      : status_(original_status),
        line_(line),
        file_(file),
        stream_(new std::ostringstream) {}

  bool ok() const { return status_.ok(); }

  StatusBuilder& SetAppend();

  StatusBuilder& SetPrepend();

  StatusBuilder& SetNoLogging();

  template <typename T>
  StatusBuilder& operator<<(const T& msg) {
    if (status_.ok()) return *this;
    *stream_ << msg;
    return *this;
  }

  operator Status() const&;
  operator Status() &&;

  ::util::Status JoinMessageToStatus();

 private:
  // Specifies how to join the error message in the original status and any
  // additional message that has been streamed into the builder.
  enum class MessageJoinStyle {
    kAnnotate,
    kAppend,
    kPrepend,
  };

  // The status that the result will be based on.
  ::util::Status status_;
  // The line to record if this file is logged.
  int line_;
  // Not-owned: The file to record if this status is logged.
  const char* file_;
  bool no_logging_ = false;
  // The additional messages added with `<<`.
  std::unique_ptr<std::ostringstream> stream_;
  // Specifies how to join the message in `status_` and `stream_`.
  MessageJoinStyle join_style_ = MessageJoinStyle::kAnnotate;
};

inline StatusBuilder AlreadyExistsErrorBuilder(
    ::util::source_location location) {
  return StatusBuilder(::util::StatusCode::kAlreadyExists, location);
}

inline StatusBuilder FailedPreconditionErrorBuilder(
    ::util::source_location location) {
  return StatusBuilder(::util::StatusCode::kFailedPrecondition, location);
}

inline StatusBuilder InternalErrorBuilder(
    ::util::source_location location) {
  return StatusBuilder(::util::StatusCode::kInternal, location);
}

inline StatusBuilder InvalidArgumentErrorBuilder(
    ::util::source_location location) {
  return StatusBuilder(::util::StatusCode::kInvalidArgument, location);
}

inline StatusBuilder NotFoundErrorBuilder(
    ::util::source_location location) {
  return StatusBuilder(::util::StatusCode::kNotFound, location);
}

inline StatusBuilder UnavailableErrorBuilder(
    ::util::source_location location) {
  return StatusBuilder(::util::StatusCode::kUnavailable, location);
}

inline StatusBuilder UnimplementedErrorBuilder(
    ::util::source_location location) {
  return StatusBuilder(::util::StatusCode::kUnimplemented, location);
}

inline StatusBuilder UnknownErrorBuilder(
    ::util::source_location location) {
  return StatusBuilder(::util::StatusCode::kUnknown, location);
}

}  // namespace util

#endif  // MEDIAPIPE_DEPS_STATUS_BUILDER_H_
