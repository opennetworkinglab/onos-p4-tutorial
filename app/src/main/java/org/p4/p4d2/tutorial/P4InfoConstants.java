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

package org.p4.p4d2.tutorial;

import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiActionProfileId;
import org.onosproject.net.pi.model.PiPacketMetadataId;
import org.onosproject.net.pi.model.PiCounterId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
/**
 * P4Info constants.
 */
public final class P4InfoConstants {

    // hide default constructor
    private P4InfoConstants() {
    }

    // Header field IDs
    public static final PiMatchFieldId HDR_ETHERNET_ETHER_TYPE =
            PiMatchFieldId.of("hdr.ethernet.ether_type");
    public static final PiMatchFieldId HDR_FABRIC_METADATA_L4_DST_PORT =
            PiMatchFieldId.of("fabric_metadata.l4_dst_port");
    public static final PiMatchFieldId HDR_ETHERNET_SRC_ADDR =
            PiMatchFieldId.of("hdr.ethernet.src_addr");
    public static final PiMatchFieldId HDR_ICMP_ICMP_TYPE =
            PiMatchFieldId.of("hdr.icmp.icmp_type");
    public static final PiMatchFieldId HDR_STANDARD_METADATA_INGRESS_PORT =
            PiMatchFieldId.of("standard_metadata.ingress_port");
    public static final PiMatchFieldId HDR_IPV6_DST_ADDR =
            PiMatchFieldId.of("hdr.ipv6.dst_addr");
    public static final PiMatchFieldId HDR_FABRIC_METADATA_IP_PROTO =
            PiMatchFieldId.of("fabric_metadata.ip_proto");
    public static final PiMatchFieldId HDR_FABRIC_METADATA_L4_SRC_PORT =
            PiMatchFieldId.of("fabric_metadata.l4_src_port");
    public static final PiMatchFieldId HDR_ETHERNET_DST_ADDR =
            PiMatchFieldId.of("hdr.ethernet.dst_addr");
    public static final PiMatchFieldId HDR_ICMP_ICMP_CODE =
            PiMatchFieldId.of("hdr.icmp.icmp_code");
    public static final PiMatchFieldId HDR_NDP_TARGET_ADDR =
            PiMatchFieldId.of("hdr.ndp.target_addr");
    // Table IDs
    public static final PiTableId FABRIC_INGRESS_L3_TABLE =
            PiTableId.of("FabricIngress.l3_table");
    public static final PiTableId FABRIC_INGRESS_SRV6_TRANSIT =
            PiTableId.of("FabricIngress.srv6_transit");
    public static final PiTableId FABRIC_INGRESS_L2_TABLE =
            PiTableId.of("FabricIngress.l2_exact_table");
    public static final PiTableId FABRIC_INGRESS_L2_BROADCAST_TABLE =
            PiTableId.of("FabricIngress.l2_ternary_table");
    public static final PiTableId FABRIC_INGRESS_L2_MY_STATION =
            PiTableId.of("FabricIngress.l2_my_station");
    public static final PiTableId FABRIC_INGRESS_SRV6_MY_SID =
            PiTableId.of("FabricIngress.srv6_my_sid");
    public static final PiTableId FABRIC_INGRESS_ACL =
            PiTableId.of("FabricIngress.acl");
    public static final PiTableId FABRIC_INGRESS_NDP_REPLY =
            PiTableId.of("FabricIngress.ndp_reply");

    // Action IDs
    public static final PiActionId FABRIC_INGRESS_SRV6_END =
            PiActionId.of("FabricIngress.srv6_end");
    public static final PiActionId FABRIC_INGRESS_SRV6_POP =
            PiActionId.of("FabricIngress.srv6_pop");
    public static final PiActionId FABRIC_INGRESS_SET_L2_NEXT_HOP =
            PiActionId.of("FabricIngress.set_l2_next_hop");
    public static final PiActionId FABRIC_INGRESS_PUNT_TO_CPU =
            PiActionId.of("FabricIngress.punt_to_cpu");
    public static final PiActionId FABRIC_INGRESS_L2_UNICAST_FWD =
            PiActionId.of("FabricIngress.set_output_port");
    public static final PiActionId FABRIC_INGRESS_L2_BROADCAST_FWD =
            PiActionId.of("FabricIngress.l2_broadcast_fwd");
    public static final PiActionId FABRIC_INGRESS_SRV6_T_INSERT_3 =
            PiActionId.of("FabricIngress.srv6_t_insert_3");
    public static final PiActionId NO_ACTION = PiActionId.of("NoAction");
    public static final PiActionId FABRIC_INGRESS_CLONE_TO_CPU =
            PiActionId.of("FabricIngress.clone_to_cpu");
    public static final PiActionId FABRIC_INGRESS_DROP =
            PiActionId.of("FabricIngress.drop");
    public static final PiActionId FABRIC_INGRESS_SRV6_T_INSERT_2 =
            PiActionId.of("FabricIngress.srv6_t_insert_2");
    public static final PiActionId FABRIC_INGRESS_L2_MULTICAST_FWD =
            PiActionId.of("FabricIngress.set_multicast_group");
    public static final PiActionId FABRIC_INGRESS_NDP_ADVERTISEMENT =
            PiActionId.of("FabricIngress.ndp_advertisement");

    // Action Param IDs
    public static final PiActionParamId DMAC = PiActionParamId.of("dmac");
    public static final PiActionParamId S3 = PiActionParamId.of("s3");
    public static final PiActionParamId S2 = PiActionParamId.of("s2");
    public static final PiActionParamId S1 = PiActionParamId.of("s1");
    public static final PiActionParamId PORT_NUM =
            PiActionParamId.of("port_num");
    public static final PiActionParamId GID = PiActionParamId.of("gid");
    public static final PiActionParamId ROUTER_MAC = PiActionParamId.of("router_mac");
    // Action Profile IDs
    public static final PiActionProfileId FABRIC_INGRESS_ECMP_SELECTOR =
            PiActionProfileId.of("FabricIngress.ecmp_selector");
    // Packet Metadata IDs
    public static final PiPacketMetadataId INGRESS_PORT =
            PiPacketMetadataId.of("ingress_port");
    public static final PiPacketMetadataId EGRESS_PORT =
            PiPacketMetadataId.of("egress_port");
}
