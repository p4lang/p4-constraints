// Copyright 2020 The P4-Constraints Authors
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

#ifndef THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_CONSTRAINT_SOURCE_H_
#define THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_CONSTRAINT_SOURCE_H_

#include <string>

#include "p4_constraints/ast.pb.h"

namespace p4_constraints {

// Convenient struct of source information for quoting.
struct ConstraintSource {
  std::string constraint_string;
  ast::SourceLocation constraint_location;
};

}  // namespace p4_constraints

#endif  // THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_CONSTRAINT_SOURCE_H_
