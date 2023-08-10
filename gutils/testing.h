// Copyright 2023 Google LLC
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

#ifndef P4LANG_P4_CONSTRAINTS_GUTILS_TESTING_H_
#define P4LANG_P4_CONSTRAINTS_GUTILS_TESTING_H_

#include <string>

#include "absl/strings/string_view.h"

namespace gutils {

// Takes a snake_case string and returns a CamelCase string. If `lower_first` is
// set, the first character will be lowercase (if a letter) and otherwise it
// will be uppercase.
// Used to e.g. convert snake case strings to GTEST compatible test names.
std::string SnakeCaseToCamelCase(absl::string_view input,
                                 bool lower_first = false);

}  // namespace gutils

#endif  // P4LANG_P4_CONSTRAINTS_GUTILS_TESTING_H_
