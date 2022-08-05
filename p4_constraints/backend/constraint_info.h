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

#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "absl/types/variant.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"

namespace p4_constraints {

struct KeyInfo {
  uint32_t id;       // Same as MatchField.id in p4info.proto.
  std::string name;  // Same as MatchField.name in p4info.proto.

  // Key type specifying how many bits to match on and how, e.g. Ternary<16>.
  // Derives from MatchField.match_type and MatchField.bitwidth in p4info.proto.
  ast::Type type;
};

struct TableInfo {
  uint32_t id;       // Same as Table.preamble.id in p4info.proto.
  std::string name;  // Same as Table.preamble.name in p4info.proto.

  // An optional constraint (aka entry_restriction) on table entries.
  absl::optional<ast::Expression> constraint;
  // If member `constraint` is present, this captures its source. Aribitray
  // otherwise
  ConstraintSource constraint_source;

  // Maps from key IDs/names to KeyInfo.
  // Derives from Table.match_fields in p4info.proto.
  absl::flat_hash_map<uint32_t, KeyInfo> keys_by_id;
  absl::flat_hash_map<std::string, KeyInfo> keys_by_name;
};

// Contains all information required for constraint checking.
// Technically, a map from table IDs to TableInfo.
using ConstraintInfo = absl::flat_hash_map<uint32_t, TableInfo>;

// Translates P4Info to ConstraintInfo.
//
// Parses all tables and their constraint annotations into an in-memory
// representation suitable for constraint checking. Returns parsed
// representation, or an error statuses if parsing fails.
absl::StatusOr<ConstraintInfo> P4ToConstraintInfo(
    const p4::config::v1::P4Info& p4info);

// Table entry metadata accessible in the constraint language, e.g. priority.
struct MetadataInfo {
  std::string name;
  ast::Type type;
};

// Returns information for a given metadata name, std::nullopt for unknown
// metadata.
std::optional<MetadataInfo> GetMetadataInfo(absl::string_view metadata_name);

}  // namespace p4_constraints

#endif  // P4_CONSTRAINTS_BACKEND_CONSTRAINT_INFO_H_
