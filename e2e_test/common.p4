#include <v1model.p4>

#define IPv4_ETHER_TYPE 0x0800
#define IPv6_ETHER_TYPE 0x86DD

typedef bit<48> ethernet_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;

header ethernet_t {
  ethernet_addr_t dst_addr;
  ethernet_addr_t src_addr;
  bit<16> ether_type;
}

header ipv4_t {
  ipv4_addr_t src_addr;
  ipv4_addr_t dst_addr;
}

header ipv6_t {
  ipv6_addr_t src_addr;
  ipv6_addr_t dst_addr;
}

struct headers_t {
  ethernet_t ethernet;
  ipv4_t ipv4;
  ipv6_t ipv6;
}

struct local_metadata_t {
  bool is_ip_packet;
  bit<6> dscp;
}

parser packet_paser(packet_in b,
                    out headers_t headers,
                    inout local_metadata_t local_metadata,
                    inout standard_metadata_t standard_metadata) {
  state start {
    transition accept;
  }
}

control verify_ipv4_checksum(inout headers_t headers,
                             inout local_metadata_t m) {
  apply { }
}

control compute_ipv4_checksum(inout headers_t headers,
                              inout local_metadata_t m) {
  apply { }
}

control egress(inout headers_t headers,
               inout local_metadata_t local_metadata,
               inout standard_metadata_t standard_metadata) {
  apply { }
}

control deparser(packet_out b, in headers_t headers) {
  apply { }
}
