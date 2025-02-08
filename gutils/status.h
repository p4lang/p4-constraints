/*
 * Copyright 2022 The P4-Constraints Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_STATUS_H_
#define THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_STATUS_H_

#include <string>

#include "absl/status/status.h"

namespace gutils {

// Converts `status` to a readable string. The current absl `ToString` method is
// not stable, which causes issues while golden testing. This function is
// stable.
std::string StableStatusToString(const absl::Status& status);

}  // namespace gutils

#endif  // THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_STATUS_H_
