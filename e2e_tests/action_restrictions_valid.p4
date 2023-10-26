#include <v1model.p4>

struct headers {};
struct metadata {
  bit<16> foo;
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

  table tbl {
    key = {  }
    actions = {
      act_1;
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
