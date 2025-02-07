/*
 * Copyright 2023 The P4-Constraints Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef P4_CONSTRAINTS_FRONTEND_CONSTRAINT_KIND_H_
#define P4_CONSTRAINTS_FRONTEND_CONSTRAINT_KIND_H_

namespace p4_constraints {

enum class ConstraintKind {
  // Constraint attached to a P4 table using an `@entry_restriction` annotation.
  kTableConstraint,
  // Constraint attached to a P4 action using an `@action_restriction`
  // annotation.
  kActionConstraint,
};

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_FRONTEND_CONSTRAINT_KIND_H_
