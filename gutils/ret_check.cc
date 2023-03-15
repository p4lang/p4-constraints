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

#include "gutils/ret_check.h"

#include "absl/status/status.h"

namespace gutils {

::gutils::StatusBuilder RetCheckFailSlowPath(
    ::gutils::SourceLocation location) {
  // TODO Implement LogWithStackTrace().
  return ::gutils::InternalErrorBuilder(location)
         << "RET_CHECK failure (" << location.file_name() << ":"
         << location.line() << ") ";
}

::gutils::StatusBuilder RetCheckFailSlowPath(::gutils::SourceLocation location,
                                             const char* condition) {
  return ::gutils::RetCheckFailSlowPath(location) << condition;
}

::gutils::StatusBuilder RetCheckFailSlowPath(::gutils::SourceLocation location,
                                             const char* condition,
                                             const ::absl::Status& status) {
  return ::gutils::RetCheckFailSlowPath(location)
         << condition << " returned " << status << " ";
}

}  // namespace gutils
