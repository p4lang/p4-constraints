/*
 * Copyright 2020 The P4-Constraints Authors
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

// Data structure containing all info required for constraint checking.
//
// ConstraintInfo is a data structure containing all information required for
// checking that a table entry satisfies the constraints specified in the P4
// program. ConstraintInfo can be parsed from a P4Info protobuf.

#ifndef P4_CONSTRAINTS_BACKEND_CONSTRAINT_INFO_H_
#define P4_CONSTRAINTS_BACKEND_CONSTRAINT_INFO_H_

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "util/integral_types.h"
#include "p4_constraints/ast.pb.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "p4/config/v1/p4info.pb.h"

namespace p4_constraints {

struct KeyInfo {
  uint32 id;         // Same as MatchField.id in p4info.proto.
  std::string name;  // Same as MatchField.name in p4info.proto.

  // Key type specifying how many bits to match on and how, e.g. Ternary<16>.
  // Derives from MatchField.match_type and MatchField.bitwidth in p4info.proto.
  ast::Type type;
};

struct TableInfo {
  uint32 id;         // Same as Table.preamble.id in p4info.proto.
  std::string name;  // Same as Table.preamble.name in p4info.proto.

  // An optional constraint (aka entry_restriction) on table entries.
  absl::optional<ast::Expression> constraint;

  // Maps from key IDs/names to KeyInfo.
  // Derives from Table.match_fields in p4info.proto.
  absl::flat_hash_map<const uint32, const KeyInfo> keys_by_id;
  absl::flat_hash_map<const std::string, const KeyInfo> keys_by_name;
};

// Contains all information required for constraint checking.
// Technically, a map from table IDs to TableInfo.
using ConstraintInfo = const absl::flat_hash_map<const uint32, const TableInfo>;

// Translates P4Info to ConstraintInfo.
//
// Parses all tables and their constraint annotations into an in-memory
// representation suitable for constraint checking. Returns parsed
// representation together with list of error statuses that may have occurred.
// If the list of statuses is non-empty, the returned `ConstraintInfo` is
// incomplete and must be discarded by the caller.
std::pair<ConstraintInfo, std::vector<absl::Status>> P4ToConstraintInfo(
    const p4::config::v1::P4Info& p4info);

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_BACKEND_CONSTRAINT_INFO_H_
