// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "util/status_builder.h"

#include <cstdio>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"

namespace {

// Returns a Status that is identical to `s` except that the message()
// has been augmented by adding `msg` to the end of the original message.
absl::Status Annotate(const absl::Status& s, absl::string_view msg) {
  if (s.ok() || msg.empty()) return s;

  absl::string_view new_msg = msg;
  std::string annotated;
  if (!s.message().empty()) {
    absl::StrAppend(&annotated, s.message(), "; ", msg);
    new_msg = annotated;
  }
  absl::Status result(s.code(), new_msg);
  // TODO(scotttodd): Copy payload(s) into the new Status
  return result;
}

}  // namespace

namespace util {

StatusBuilder::StatusBuilder(const absl::Status& original_status,
                             SourceLocation location)
    : status_(original_status), loc_(location) {}

StatusBuilder::StatusBuilder(absl::Status&& original_status,
                             SourceLocation location)
    : status_(original_status), loc_(location) {}

StatusBuilder::StatusBuilder(const StatusBuilder& sb)
    : status_(sb.status_), loc_(sb.loc_), stream_(sb.stream_.str()) {}

StatusBuilder::StatusBuilder(absl::StatusCode code, SourceLocation location)
    : status_(code, ""), loc_(location) {}

StatusBuilder& StatusBuilder::operator=(const StatusBuilder& sb) {
  status_ = sb.status_;
  loc_ = sb.loc_;
  stream_ = std::stringstream(sb.stream_.str());
  return *this;
}

StatusBuilder::operator absl::Status() const& {
  return StatusBuilder(*this).CreateStatus();
}
StatusBuilder::operator absl::Status() && {
  return std::move(*this).CreateStatus();
}

bool StatusBuilder::ok() const { return status_.ok(); }

absl::StatusCode StatusBuilder::code() const { return status_.code(); }

SourceLocation StatusBuilder::source_location() const { return loc_; }

absl::Status StatusBuilder::CreateStatus() && {
  absl::Status result = JoinMessageToStatus(status_, stream_.str());

  // Reset the status after consuming it.
  status_ = absl::UnknownError("");
  stream_ = std::stringstream();
  return result;
}

absl::Status StatusBuilder::JoinMessageToStatus(absl::Status s,
                                                absl::string_view msg) {
  if (msg.empty()) return s;
  return Annotate(s, msg);
}

std::ostream& operator<<(std::ostream& os, const StatusBuilder& builder) {
  return os << static_cast<absl::Status>(builder);
}

std::ostream& operator<<(std::ostream& os, StatusBuilder&& builder) {
  return os << static_cast<absl::Status>(std::move(builder));
}

StatusBuilder AbortedErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kAborted, location);
}

StatusBuilder AlreadyExistsErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kAlreadyExists, location);
}

StatusBuilder CancelledErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kCancelled, location);
}

StatusBuilder DataLossErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kDataLoss, location);
}

StatusBuilder DeadlineExceededErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kDeadlineExceeded, location);
}

StatusBuilder FailedPreconditionErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kFailedPrecondition, location);
}

StatusBuilder InternalErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kInternal, location);
}

StatusBuilder InvalidArgumentErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kInvalidArgument, location);
}

StatusBuilder NotFoundErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kNotFound, location);
}

StatusBuilder OutOfRangeErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kOutOfRange, location);
}

StatusBuilder PermissionDeniedErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kPermissionDenied, location);
}

StatusBuilder UnauthenticatedErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kUnauthenticated, location);
}

StatusBuilder ResourceExhaustedErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kResourceExhausted, location);
}

StatusBuilder UnavailableErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kUnavailable, location);
}

StatusBuilder UnimplementedErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kUnimplemented, location);
}

StatusBuilder UnknownErrorBuilder(SourceLocation location) {
  return StatusBuilder(absl::StatusCode::kUnknown, location);
}

}  // namespace util
