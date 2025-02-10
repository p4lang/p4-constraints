// Copyright 2023 The P4-Constraints Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include "p4_constraints/backend/constraint_info.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string_view>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "gutils/proto.h"
#include "gutils/status_matchers.h"
#include "p4/config/v1/p4info.pb.h"

using p4::config::v1::P4Info;

namespace p4_constraints {

class P4ToConstraintInfoTest : public ::testing::Test {};

TEST(P4ToConstraintInfoTest, ValidActionRestrictionSucceeds) {
  P4Info p4_info;

  std::string_view proto_string =
      R"pb(
    actions {
      preamble {
        id: 123
        name: "MyIngress.act_1"
        alias: "act_1"
        annotations: "@action_restriction(\"multicast_group_id != 0\")"
      }
      params {
        id: 1
        name: "multicast_group_id"
        bitwidth: 16,
      }
    }
      )pb";

  ASSERT_OK(gutils::ReadProtoFromString(proto_string, &p4_info));

  absl::StatusOr<ConstraintInfo> constraints =
      p4_constraints::P4ToConstraintInfo(p4_info);

  ASSERT_OK(constraints);

  absl::flat_hash_map<uint32_t, ActionInfo> action_info_by_id =
      constraints.value().action_info_by_id;

  EXPECT_EQ(action_info_by_id[123].constraint_source.constraint_string,
            "multicast_group_id != 0");
}

TEST(P4ToConstraintInfoTest, ActionWithP4NamedTypeConstraintFails) {
  P4Info p4_info;

  std::string_view proto_string =
      R"pb(
    actions {
      preamble {
        id: 123
        name: "MyIngress.act_2"
        alias: "act_2"
        annotations: "@action_restriction(\"custom_type_param != 0\")"
      }
      params {
        id: 1
        name: "custom_type_param"
        bitwidth: 16
        type_name { name: "custom_type_t" }
      }
    }
      )pb";

  ASSERT_OK(gutils::ReadProtoFromString(proto_string, &p4_info));

  absl::StatusOr<ConstraintInfo> constraints =
      p4_constraints::P4ToConstraintInfo(p4_info);

  EXPECT_TRUE(!constraints.ok());
}

TEST(P4ToConstraintInfoTest, ConstraintAnnotationsMustBeEnclosedInParen) {
  P4Info p4_info;

  std::string_view proto_string =
      R"pb(
    actions {
      preamble {
        id: 123
        name: "MyIngress.act_1"
        alias: "act_1"
        annotations: "@action_restriction x != 0"
      }
    }
      )pb";
  ASSERT_OK(gutils::ReadProtoFromString(proto_string, &p4_info));

  absl::StatusOr<ConstraintInfo> constraints =
      p4_constraints::P4ToConstraintInfo(p4_info);

  ASSERT_EQ(
      R"s(P4Info to constraint info translation failed with the following errors:
- In action MyIngress.act_1:
Syntax error: @action_restriction must be enclosed in '("' and '")'
)s",
      constraints.status().message());

  ASSERT_TRUE(!constraints.status().ok());
}

TEST(GetTableInfoOrNullTest, ShouldGetNonNullptrToTableInfo) {
  P4Info p4_info;

  ASSERT_OK(gutils::ReadProtoFromString(R"pb(
                                          tables {
                                            preamble {
                                              id: 1
                                              name: "table",
                                            }
                                          }
                                        )pb",
                                        &p4_info));

  ASSERT_OK_AND_ASSIGN(ConstraintInfo constraints,
                       p4_constraints::P4ToConstraintInfo(p4_info));

  ASSERT_NE(GetTableInfoOrNull(constraints, 1), nullptr);
}

TEST(GetActionInfoOrNullTest, ShouldGetNonNullptrToActionInfo) {
  P4Info p4_info;

  ASSERT_OK(gutils::ReadProtoFromString(
      R"pb(
        actions {
          preamble {
            id: 123
            name: "MyIngress.act_1"
            alias: "act_1",
          }
        }
      )pb",
      &p4_info));

  ASSERT_OK_AND_ASSIGN(ConstraintInfo constraints,
                       p4_constraints::P4ToConstraintInfo(p4_info));

  ASSERT_NE(GetActionInfoOrNull(constraints, 123), nullptr);
}

}  // namespace p4_constraints
