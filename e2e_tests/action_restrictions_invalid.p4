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

#include <v1model.p4>

type bit<16> custom_type_t;

struct headers {};
struct metadata {
  bit<16> foo;
  custom_type_t bar;
};

#define MULTICAST_GROUP_ID_BITWIDTH 16
typedef bit<MULTICAST_GROUP_ID_BITWIDTH> multicast_group_id_t;

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
  state start {
    transition accept;
  }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
  apply {  }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

  @id(123)
  @action_restriction("multicast_group_id != 0")
  action act_1(multicast_group_id_t multicast_group_id) {
    meta.foo = multicast_group_id;
  }

  @id(1234)
  @action_restriction("custom_type_param != 0")
  action act_2(custom_type_t custom_type_param) {
    meta.bar = custom_type_param;
  }

  table tbl {
    key = {  }
    actions = {
      act_1;
      act_2;
    }
  }

  apply {
    tbl.apply();
  }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
  apply {  }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
  apply {  }
}

control MyDeparser(packet_out packet, in headers hdr) {
  apply {  }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
