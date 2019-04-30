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

    action drop() {
        mark_to_drop();
    }

    /*
     * NDP reply table and actions.
     * Handles NDP router solicitation message and send router advertisement to the sender.
     */
    action ndp_ns_to_na(mac_addr_t target_mac) {
        hdr.ethernet.src_addr = target_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        bit<128> host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp_option.setValid();
        hdr.ndp_option.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp_option.length = 1;
        hdr.ndp_option.value = target_mac;
        hdr.ipv6.next_hdr = PROTO_ICMPV6;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        fabric_metadata.skip_l2 = true;
    }

    direct_counter(CounterType.packets_and_bytes) ndp_reply_table_counter;
    table ndp_reply_table {
        key = {
            hdr.ndp.target_addr: exact;
        }
        actions = {
            ndp_ns_to_na;
        }
        counters = ndp_reply_table_counter;
    }

    /*
     * TODO EXERCISE 2
     * Create L2 table(s). Our solution uses two tables: one for unicast and one for broadcast/multicast.
     * We have already provided both the unicast (set_output_port) and multicast (set_multicast_group)
     * actions for you to use.
     * If you choose to use two tables, what should the default actions be for each table?
     * You should add a direct counter to the table if you would like to see flow stats in ONOS.
     * Matches the destination Ethernet address and set output port or do nothing.
     */
    action set_output_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }
    action set_multicast_group(group_id_t gid) {
        standard_metadata.mcast_grp = gid;
        fabric_metadata.is_multicast = true;
    }


    /*
     * TODO EXERCISE 3
     * Create a L2 my station table.
     * Hit when Ethernet destination address is the device address.
     * This table won't do anything to the packet, but the pipeline will use the result (table.hit)
     * to decide how to process the packet. (Use NoAction for flow entries.)
     */


    /*
     * TODO EXERCISE 3
     * Create a L3 table for IPv6 routing.
     * Handles IPv6 routing. Pick a next hop address according to hash of packet header fields
     * (IPv6 source/destination address and the flow label).
     */
    action_selector(HashAlgorithm.crc16, 32w64, 32w16) ecmp_selector;
    direct_counter(CounterType.packets_and_bytes) l3_table_counter;


    /*
     * TODO EXERCISE 4
     * Create a SRv6 my sid table and SRv6 endpoint action. The table should process the packet if
     * the destination IP is the Segemnt Id (sid) of this device.
     *
     * For matches in this table, the switch should perform the "end" action which will decrement the
     * "segment left" field from the Srv6 header and set destination IP address to next segment.
     *
     * You can create direct counter for this table if you would like to track flow stats in ONOS.
     */


    /*
     * SRv6 transit table.
     * Inserts the SRv6 header to the IPv6 header of the packet based on the destination IP address.
     */
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
          // TODO EXERCISE 4
          // Add match fields for SRv6 transit rules; we'll start with the destination IP address
      }
      actions = {
          srv6_t_insert_2;
          srv6_t_insert_3;
          // Extra credit: set a metadata field, then push label stack in egress
      }
      counters = srv6_transit_table_counter;
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

    /*
     * ACL table  and actions.
     * Clone the packet to the CPU (PacketIn) or drop.
     */

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

    apply {
        if (hdr.packet_out.isValid()) {
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }

        if (hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {
            ndp_reply_table.apply();
        }

        // TODO EXERCISE 3
        // Insert logic to match the My Station table and upon hit, the routing table. You should also
        // add a conditional to drop the packet if the hop_limit reaches 0.

        // TODO EXERCISE 4
        // Insert logic to match the SRv6 My SID and Transit tables as well as logic to perform PSP behavior
        // HINT: This logic belongs somewhere between checking the switch's my station table and applying the
        //       routing table.

        // TODO EXERCISE 2
        // Insert logic to apply your L2 table(s). You probably want to chain them together with a conditional
        // based on whether or not there was a hit in the first one.

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
