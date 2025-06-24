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

#include "p4_constraints/ret_check.h"

#include "absl/status/status.h"
#include "gutil/status.h"
#include "p4_constraints/source_location.h"

gutil::StatusBuilder RetCheckFailSlowPath(
    p4_constraints::SourceLocation location) {
  // TODO Implement LogWithStackTrace().
  return gutil::InternalErrorBuilder()
         << "RET_CHECK failure (" << location.file_name() << ":"
         << location.line() << ") ";
}

gutil::StatusBuilder RetCheckFailSlowPath(
    p4_constraints::SourceLocation location, const char* condition) {
  return RetCheckFailSlowPath(location) << condition;
}

gutil::StatusBuilder RetCheckFailSlowPath(
    p4_constraints::SourceLocation location, const char* condition,
    const ::absl::Status& status) {
  return RetCheckFailSlowPath(location)
         << condition << " returned " << status << " ";
}
