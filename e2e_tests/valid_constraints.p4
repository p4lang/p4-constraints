// Copyright 2021 The P4-Constraints Authors
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

#include "common.p4"

control valid_constraints(inout headers_t hdr,
                          inout local_metadata_t local_metadata,
                          inout standard_metadata_t standard_metadata) {
  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("true")
  @id(1)
  table accept_all_entries { key = {} actions = {} }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("false")
  @id(2)
  table reject_all_entries { key = {} actions = {} }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    // Either wildcard or exact match (i.e., 'optional' match).
    hdr.ipv4.dst_addr::mask == 0 || hdr.ipv4.dst_addr::mask == -1;

    // Only match on IPv4 addresses of IPv4 packets.
    hdr.ipv4.dst_addr::mask != 0 ->
      hdr.ethernet.ether_type == IPv4_ETHER_TYPE;

    // Only match on IPv6 addresses of IPv6 packets.
    hdr.ipv6.dst_addr::mask != 0 ->
      hdr.ethernet.ether_type == IPv6_ETHER_TYPE;

    local_metadata.dscp::mask != 0 -> (
      hdr.ethernet.ether_type == IPv4_ETHER_TYPE ||
      hdr.ethernet.ether_type == IPv6_ETHER_TYPE ||
      local_metadata.is_ip_packet == 1
    );
  ")
  @id(3)
  table vrf_classifier_table {
    key = {
      hdr.ethernet.ether_type : ternary;
      hdr.ethernet.src_addr : ternary;
      hdr.ipv4.dst_addr : ternary;
      standard_metadata.ingress_port: ternary;
      hdr.ipv6.dst_addr : ternary;
      hdr.ipv4.src_addr : optional;
      local_metadata.dscp : ternary;
      local_metadata.is_ip_packet : ternary;
    }
    actions = { }
  }


  @file(__FILE__)
  @line(__LINE__)
  // Tests that multiline strings also work.
  @entry_restriction(
    // Either wildcard or exact match (i.e., "optional" match).
    "hdr.ipv4.dst_addr::mask == 0 || hdr.ipv4.dst_addr::mask == -1;"

    // Only match on IPv4 addresses of IPv4 packets.
    "hdr.ipv4.dst_addr::mask != 0 ->     "
    // Macros are not usable within a single-line string.
    "  hdr.ethernet.ether_type == 0x0800;"

    // Only match on IPv6 addresses of IPv6 packets.
    "hdr.ipv6.dst_addr::mask != 0 ->
      hdr.ethernet.ether_type == IPv6_ETHER_TYPE;

    local_metadata.dscp::mask != 0 -> (
      hdr.ethernet.ether_type == IPv4_ETHER_TYPE ||
      hdr.ethernet.ether_type == IPv6_ETHER_TYPE ||
      local_metadata.is_ip_packet == 1
    );
  ")
  @id(6)
  table vrf_classifier_table_with_multiline_strings {
    key = {
      hdr.ethernet.ether_type : ternary;
      hdr.ethernet.src_addr : ternary;
      hdr.ipv4.dst_addr : ternary;
      standard_metadata.ingress_port: ternary;
      hdr.ipv6.dst_addr : ternary;
      hdr.ipv4.src_addr : optional;
      local_metadata.dscp : ternary;
      local_metadata.is_ip_packet : ternary;
    }
    actions = { }
  }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    // Vacuously true, just to test syntax and implicit conversions.
    hdr.ipv4.dst_addr::mask == 0 || hdr.ipv4.dst_addr::mask == -1;
    hdr.ipv4.dst_addr::value == 10 || hdr.ipv4.dst_addr::value != 10;
    // Same as above, but using implicit conversion.
    hdr.ipv4.dst_addr == 10 || hdr.ipv4.dst_addr != 10;
    // A real constraint: only wildcard match is okay.
    hdr.ipv4.dst_addr::mask == 0;
    // A constraint on metadata.
    ::priority < 0x7fffffff;
  ")
  @id(4)
  table optional_match_table {
    key = { hdr.ipv4.dst_addr : optional; }
    actions = {}
  }

  @entry_restriction("
    hdr.ethernet.dst_addr::value < mac('00:00:00:00:00:05');
    hdr.ipv4.dst_addr == ipv4('0.0.0.255');
    hdr.ipv6.dst_addr::value > ipv6('::');
  ")
  @id(5)
  table network_address_table {
    key = {
      hdr.ethernet.dst_addr : exact;
      hdr.ipv4.dst_addr : exact;
      hdr.ipv6.dst_addr : exact;
    }
    actions = { }
  }

  apply {
    accept_all_entries.apply();
    reject_all_entries.apply();
    vrf_classifier_table.apply();
    optional_match_table.apply();
    network_address_table.apply();
    vrf_classifier_table_with_multiline_strings.apply();
  }
}

V1Switch(packet_paser(), verify_ipv4_checksum(), valid_constraints(),
         egress(), compute_ipv4_checksum(), deparser()) main;
