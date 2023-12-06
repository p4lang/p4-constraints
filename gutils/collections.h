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

#ifndef P4LANG_P4_CONSTRAINTS_GUTILS_COLLECTIONS_H_
#define P4LANG_P4_CONSTRAINTS_GUTILS_COLLECTIONS_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"

namespace gutils {

// Returns a non-null pointer of the value associated with a given key
// if it exists, or a status failure if it does not.
// Only defined on maps where the key can be stringified by StrCat.
template <typename M, typename KeyType = typename M::key_type>
absl::StatusOr<const typename M::mapped_type *> FindPtrOrStatus(
    const M &m, const KeyType &k) {
  auto it = m.find(k);
  if (it != m.end()) return &it->second;
  return absl::NotFoundError(absl::StrCat("Key not found: '", k, "'"));
}

}  // namespace gutils

#endif  // P4LANG_P4_CONSTRAINTS_GUTILS_COLLECTIONS_H_
