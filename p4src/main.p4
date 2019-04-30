/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <core.p4>
#include <v1model.p4>

#include "include/header.p4"
#include "include/parser.p4"
#include "include/checksum.p4"

#define CPU_CLONE_SESSION_ID 99


control FabricIngress (inout parsed_headers_t hdr,
                       inout fabric_metadata_t fabric_metadata,
                       inout standard_metadata_t standard_metadata) {
    // TODO add name annotations to avoid using the fully qualified names
    //  for tables etc.

    action drop() {
        mark_to_drop();
    }

    action ndp_advertisement(mac_addr_t router_mac) {
        hdr.ethernet.src_addr = router_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        bit<128> host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp_option.setValid();
        hdr.ndp_option.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp_option.length = 1;
        hdr.ndp_option.value = router_mac;
        hdr.ipv6.next_hdr = PROTO_ICMPV6;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        fabric_metadata.skip_l2 = true;
    }

    direct_counter(CounterType.packets_and_bytes) ndp_reply_table_counter;
    table ndp_reply {
        key = {
            hdr.ndp.target_addr: exact;
        }
        actions = {
            ndp_advertisement;
        }
        counters = ndp_reply_table_counter;
    }

    action set_output_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }

    action set_multicast_group(group_id_t gid) {
        standard_metadata.mcast_grp = gid;
        fabric_metadata.is_multicast = true;
    }

    direct_counter(CounterType.packets_and_bytes) l2_exact_table_counter;
    table l2_exact_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            set_output_port;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        counters = l2_exact_table_counter;
    }

    direct_counter(CounterType.packets_and_bytes) l2_ternary_table_counter;
    table l2_ternary_table {
        key = {
            hdr.ethernet.dst_addr: ternary;
        }
        actions = {
            set_multicast_group;
            drop;
        }
        const default_action = drop;
        counters = l2_ternary_table_counter;
    }

    direct_counter(CounterType.packets_and_bytes) l2_my_station_table_counter;
    table l2_my_station {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            NoAction;
        }
        counters = l2_my_station_table_counter;
    }

    action set_l2_next_hop(mac_addr_t dmac) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    action_selector(HashAlgorithm.crc16, 32w64, 32w16) ecmp_selector;
    direct_counter(CounterType.packets_and_bytes) l3_table_counter;
    table l3_table {
      key = {
          hdr.ipv6.dst_addr: lpm;

          hdr.ipv6.dst_addr: selector;
          hdr.ipv6.src_addr: selector;
          hdr.ipv6.flow_label: selector;
          // the rest of the 5-tuple is optional per RFC6438
          fabric_metadata.ip_proto: selector;
          fabric_metadata.l4_src_port: selector;
          fabric_metadata.l4_dst_port: selector;
      }
      actions = {
          set_l2_next_hop;
      }
      implementation = ecmp_selector;
      counters = l3_table_counter;
    }

    action srv6_end() {
        hdr.srv6h.segment_left = hdr.srv6h.segment_left - 1;
        hdr.ipv6.dst_addr = fabric_metadata.next_srv6_sid;
    }

    direct_counter(CounterType.packets_and_bytes) srv6_my_sid_table_counter;
    table srv6_my_sid {
      key = {
          hdr.ipv6.dst_addr: lpm;
      }
      actions = {
          srv6_end;
      }
      counters = srv6_my_sid_table_counter;
    }

    action insert_srv6h_header(bit<8> num_segments) {
        hdr.srv6h.setValid();
        hdr.srv6h.next_hdr = hdr.ipv6.next_hdr;
        hdr.srv6h.hdr_ext_len =  num_segments * 2;
        hdr.srv6h.routing_type = 4;
        hdr.srv6h.segment_left = num_segments - 1;
        hdr.srv6h.last_entry = num_segments - 1;
        hdr.srv6h.flags = 0;
        hdr.srv6h.tag = 0;
        hdr.ipv6.next_hdr = PROTO_SRV6;
    }

    /*
       Single segment header doesn't make sense given PSP
       i.e. we will pop the SRv6 header when segments_left reaches 0
     */

    action srv6_t_insert_2(ipv6_addr_t s1, ipv6_addr_t s2) {
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 40;
        insert_srv6h_header(2);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s2;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segment_id = s1;
    }

    action srv6_t_insert_3(ipv6_addr_t s1, ipv6_addr_t s2, ipv6_addr_t s3) {
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 56;
        insert_srv6h_header(3);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s3;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segment_id = s2;
        hdr.srv6_list[2].setValid();
        hdr.srv6_list[2].segment_id = s1;
    }

    direct_counter(CounterType.packets_and_bytes) srv6_transit_table_counter;
    table srv6_transit {
      key = {
          hdr.ipv6.dst_addr: lpm;
          //TODO what other fields do we want to match?
      }
      actions = {
          srv6_t_insert_2;
          srv6_t_insert_3;
          // Extra credit: set a metadata field, then push label stack in egress
      }
      counters = srv6_transit_table_counter;
    }

    action clone_to_cpu() {
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, standard_metadata);
    }

    direct_counter(CounterType.packets_and_bytes) acl_counter;
    table acl {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dst_addr: ternary;
            hdr.ethernet.src_addr: ternary;
            hdr.ethernet.ether_type: ternary;
            fabric_metadata.ip_proto: ternary;
            fabric_metadata.icmp_type: ternary;
            fabric_metadata.l4_src_port: ternary;
            fabric_metadata.l4_dst_port: ternary;
        }
        actions = {
            clone_to_cpu;
            drop;
        }
        counters = acl_counter;
    }

    action srv6_pop() {
      hdr.ipv6.next_hdr = hdr.srv6h.next_hdr;
      // SRv6 header is 8 bytes
      // SRv6 list entry is 16 bytes each
      // (((bit<16>)hdr.srv6h.last_entry + 1) * 16) + 8;
      bit<16> srv6h_size = (((bit<16>)hdr.srv6h.last_entry + 1) << 4) + 8;
      hdr.ipv6.payload_len = hdr.ipv6.payload_len - srv6h_size;

      hdr.srv6h.setInvalid();
      // Need to set MAX_HOPS headers invalid
      hdr.srv6_list[0].setInvalid();
      hdr.srv6_list[1].setInvalid();
      hdr.srv6_list[2].setInvalid();
    }

    apply {
        if (hdr.packet_out.isValid()) {
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }
        if (hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {
            ndp_reply.apply();
        }
        if (l2_my_station.apply().hit) {
            if (hdr.ipv6.isValid()) {
                if (srv6_my_sid.apply().hit) {
                    // PSP logic -- enabled for all packets
                    if (hdr.srv6h.isValid() && hdr.srv6h.segment_left == 0) {
                        srv6_pop();
                    }
                } else {
                    srv6_transit.apply();
                }
                l3_table.apply();
                if(hdr.ipv6.hop_limit == 0) {
                    drop();
                }
            }
        }
        if (!fabric_metadata.skip_l2 && standard_metadata.drop != 1w1) {
            if (!l2_exact_table.apply().hit) {
                l2_ternary_table.apply();
            }
        }

        acl.apply();
    }
}

control FabricEgress (inout parsed_headers_t hdr,
                      inout fabric_metadata_t fabric_metadata,
                      inout standard_metadata_t standard_metadata) {
    apply {
        // TODO EXERCISE 1
        // Implement logic such that if the packet is to be forwarded to the CPU
        // port, i.e. we requested a packet-in in the ingress pipeline
        // (standard_metadata.egress_port == CPU_PORT):
        // 1. Set packet_in header as valid
        // 2. Set the packet_in.ingress_port field to the original packet's
        //    ingress port (standard_metadata.ingress_port).
        // ---- START SOLUTION ----
        if (standard_metadata.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        }
        // ---- END SOLUTION ----

        if (fabric_metadata.is_multicast == true
             && standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop();
        }
    }
}

V1Switch(
    FabricParser(),
    FabricVerifyChecksum(),
    FabricIngress(),
    FabricEgress(),
    FabricComputeChecksum(),
    FabricDeparser()
) main;
