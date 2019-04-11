/*
 * Copyright 2017-present Open Networking Foundation
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


control FabricIngress (inout parsed_headers_t hdr,
                       inout fabric_metadata_t fabric_metadata,
                       inout standard_metadata_t standard_metadata) {
    // TODO add counters
    // TODO add name annotations to avoid using the fully qualified names
    //  for tables etc.

    action drop() {
        mark_to_drop();
    }

    action l2_unicast_fwd(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }

    action l2_multicast_fwd(group_id_t gid) {
        standard_metadata.mcast_grp = gid;
        fabric_metadata.is_multicast = _TRUE;
    }

    table l2_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            l2_unicast_fwd;
            l2_multicast_fwd;
            drop;
        }
        const default_action = drop;
    }

    table l2_my_station {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            NoAction;
        }
    }

    action set_l2_next_hop(mac_addr_t dmac) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    action_selector(HashAlgorithm.crc16, 32w64, 32w16) ecmp_selector;
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
    }

    action srv6_end() {
        hdr.srv6h.segment_left = hdr.srv6h.segment_left - 1;
        hdr.ipv6.dst_addr = fabric_metadata.next_srv6_sid;
    }

    table srv6_my_sid {
      key = {
          hdr.ipv6.dst_addr: ternary;
      }
      actions = {
          srv6_end;
      }
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


    table srv6_transit {
      key = {
          hdr.ipv6.dst_addr: lpm; //TODO ternary?
          //TODO what other fields do we want to match?
      }
      actions = {
          srv6_t_insert_2;
          srv6_t_insert_3;
          // Extra credit: set a metadata field, then push label stack in egress
      }
    }

    // Send immendiatelly to CPU - skip the rest of pipeline.
    action punt_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        exit;
    }

    action clone_to_cpu() {
        // FIXME: works only if pkt will be replicated via PRE multicast group.
        fabric_metadata.clone_to_cpu = _TRUE;
    }

    table acl {
        key = {
            standard_metadata.ingress_port: ternary; // 9
            hdr.ethernet.dst_addr: ternary; // 48
            hdr.ethernet.src_addr: ternary; // 48
            hdr.ethernet.ether_type: ternary; // 16
            hdr.icmp.icmp_type: ternary; // 8
            hdr.icmp.icmp_code: ternary; // 8
            fabric_metadata.ip_proto: ternary; // 8
            fabric_metadata.l4_src_port: ternary; // 16
            fabric_metadata.l4_dst_port: ternary; // 16
        }
        actions = {
            punt_to_cpu;
            clone_to_cpu;
            drop;
        }
    }

    action srv6_pop() {
      hdr.ipv6.next_hdr = hdr.srv6h.next_hdr;
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
        if (l2_my_station.apply().hit) {
        //if (l2_my_station.apply().action_run) { // can also just use .hit
           //mark_l3_fwd: {
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
           //}
        }
        if (true) { // FIXME packet not marked drop
            l2_table.apply();
        }
        acl.apply();
    }
}

control FabricEgress (inout parsed_headers_t hdr,
                      inout fabric_metadata_t fabric_metadata,
                      inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
            if (fabric_metadata.is_multicast == _TRUE &&
                fabric_metadata.clone_to_cpu == _FALSE) {
                // Is multicast but clone was not requested.
                mark_to_drop();
            }

            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        }

        if (fabric_metadata.is_multicast == _TRUE
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
