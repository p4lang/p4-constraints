// Copyright 2021 Google LLC
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

#ifndef THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_OVERLOAD_H_
#define THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_OVERLOAD_H_

namespace gutils {

// Useful in conjunction with {std,absl}::visit.
// See https://en.cppreference.com/w/cpp/utility/variant/visit.
template <class... Ts>
struct Overload : Ts... {
  using Ts::operator()...;
};
template <class... Ts>
Overload(Ts...) -> Overload<Ts...>;

}  // namespace gutils

#endif  // THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_OVERLOAD_H_
