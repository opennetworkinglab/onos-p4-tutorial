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
    //TODO add counters

    action drop() {
        mark_to_drop();
    }

    action l2_unicast_fwd(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }

    action l2_multicast_fwd(group_id_t gid) {
        standard_metadata.mcast_grp = gid;
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

    action mark_l3_fwd() {
        fabric_metadata.is_l3_fwd = true;
    }

    table l2_my_station {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            mark_l3_fwd;
        }
    }

    action set_l2_next_hop(mac_addr_t dmac) {
        //FIXME set smac
        hdr.ethernet.dst_addr = dmac;
    }

    action_selector(HashAlgorithm.crc16, 32w64, 32w16) ecmp_selector;
    table l3_table {
      key = {
          hdr.ipv6.dst_addr: lpm;
          hdr.ipv6.dst_addr: selector;
          hdr.ipv6.src_addr: selector;
          fabric_metadata.ip_proto: selector;
          fabric_metadata.l4_src_port: selector;
          fabric_metadata.l4_dst_port: selector;
      }
      actions = {
          set_l2_next_hop;
      }
      implementation = ecmp_selector;
    }

    // Send immendiatelly to CPU - skip the rest of pipeline.
    action punt_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        exit;
    }

    table acl {
        key = {
            standard_metadata.ingress_port: ternary; // 9
            hdr.ethernet.dst_addr: ternary; // 48
            hdr.ethernet.src_addr: ternary; // 48
            hdr.icmp.icmp_type: ternary; // 8
            hdr.icmp.icmp_code: ternary; // 8
            fabric_metadata.ip_proto: ternary; // 8
            fabric_metadata.l4_src_port: ternary; // 16
            fabric_metadata.l4_dst_port: ternary; // 16
        }
        actions = {
            punt_to_cpu;
            //FIXME add clone
            drop;
        }
    }

    apply {
        if (hdr.packet_out.isValid()) {
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }
        l2_my_station.apply();
        if (fabric_metadata.is_l3_fwd) {
            if (hdr.ipv6.isValid()) {
                l3_table.apply();
            }
        }
        l2_table.apply();
        acl.apply();
    }
}

control FabricEgress (inout parsed_headers_t hdr,
                      inout fabric_metadata_t fabric_metadata,
                      inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
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
