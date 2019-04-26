# Copyright 2019-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# ------------------------------------------------------------------------------
# SRV6 TESTS
#
# To run all tests:
#     make srv6
# ------------------------------------------------------------------------------

from ptf.testutils import group

from lib.base_test import *


@group("srv6")
class Srv6InsertTest(P4RuntimeTest):
    """Tests SRv6 insert behavior"""

    def runTest(self):
        sid_lists = (
            [SWITCH2_IPV6, SWITCH3_IPV6, HOST2_IPV6],
            [SWITCH2_IPV6, HOST2_IPV6],
        )
        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print "Testing %s packet with %d segments ..." % (
                    pkt_type, len(sid_list))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                self.testPacket(pkt, sid_list)

    @autocleanup
    def testPacket(self, pkt, sid_list):
        # l2_my_station -> srv6_transit -> l3_table -> l2_exact_table

        next_hop_mac = SWITCH2_MAC

        # Consider pkt's mac dst addr as my station address
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_my_station",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        # Insert SRv6 header when matching the pkt's IPV6 dst addr.
        # Action name an params are generated based on the number of SIDs given.
        # For example, with 2 SIDs:
        # action_name = FabricIngress.srv6_t_insert_2
        # action_params = {
        #     "s1": sid[0],
        #     "s2": sid[1]
        # }
        sid_len = len(sid_list)
        action_name = "FabricIngress.srv6_t_insert_%d" % sid_len
        actions_params = {"s%d" % (x + 1): sid_list[x] for x in range(sid_len)}
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.srv6_transit",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (pkt[IPv6].dst, 128)
            },
            action_name=action_name,
            action_params=actions_params
        ))

        # Insert ECMP group with only one member (next_hop_mac)
        self.insert(self.helper.build_act_prof_group(
            act_prof_name="FabricIngress.ecmp_selector",
            group_id=1,
            actions=[
                # List of tuples (action name, action param dict)
                ("FabricIngress.set_l2_next_hop", {"dmac": next_hop_mac}),
            ]
        ))

        # Map pkt's IPv6 dst addr to group
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l3_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (sid_list[0], 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Ternary match.
                "hdr.ethernet.dst_addr": next_hop_mac
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()
        # Route MAC addresses
        pkt_route(exp_pkt, next_hop_mac)
        # Set IPv6 dst to first SID...
        exp_pkt[IPv6].dst = sid_list[0]
        # Decrement TTL...
        pkt_decrement_ttl(exp_pkt)
        # Insert SRv6 header between IPv6 header and payload
        srv6_hdr = IPv6ExtHdrSegmentRouting(
            nh=pkt[IPv6].nh,
            addresses=sid_list[::-1],
            len=sid_len * 2,
            segleft=sid_len - 1,
            lastentry=sid_len - 1)
        exp_pkt[IPv6].nh = 43  # next header is SR header
        exp_pkt[IPv6].payload = srv6_hdr / pkt[IPv6].payload

        # FIXME: the P4 pipeline should calculate correct checksum
        if TCP in pkt:
            pkt[TCP].chksum = 1
            exp_pkt[TCP].chksum = 1
        if UDP in pkt:
            pkt[UDP].chksum = 1
            exp_pkt[UDP].chksum = 1
        if ICMPv6Unknown in exp_pkt:
            pkt[ICMPv6Unknown].cksum = 1
            exp_pkt[ICMPv6Unknown].cksum = 1

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)

@group("srv6")
class FabricSrv6TransitTest(P4RuntimeTest):
    """Tests SRv6 transit behavior"""

    def buildSrv6Pkt(self, pkt, sid_list):
        sid_len = len(sid_list)
        # Build srv6 packet from the given one...
        srv6_pkt = pkt.copy()
        # Route MAC addresses
        pkt_route(srv6_pkt, SWITCH1_MAC)
        # Set IPv6 dst to first SID...
        srv6_pkt[IPv6].dst = sid_list[0]
        # Insert SRv6 header between IPv6 header and payload
        srv6_hdr = IPv6ExtHdrSegmentRouting(
            nh=pkt[IPv6].nh,
            addresses=sid_list[::-1],
            len=sid_len * 2,
            segleft=sid_len,
            lastentry=sid_len - 1)
        srv6_pkt[IPv6].nh = 43  # next header is SR header
        srv6_pkt[IPv6].payload = srv6_hdr / pkt[IPv6].payload
        return srv6_pkt

    def runTest(self):
        sid_lists = (
            [SWITCH2_IPV6, SWITCH3_IPV6, HOST2_IPV6],
            [SWITCH2_IPV6, HOST2_IPV6],
        )
        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print "Testing %s packet with %d segments ..." % (
                    pkt_type, len(sid_list))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                pkt = self.buildSrv6Pkt(pkt, sid_list)
                self.testPacket(pkt, sid_list)

    @autocleanup
    def testPacket(self, pkt, sid_list):
        # l2_my_station -> l3_table -> l2_exact_table
        # No changes to SRH header
        next_hop_mac = SWITCH2_MAC

        # Consider pkt's mac dst addr as my station address
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_my_station",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        # This should be missed
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.srv6_my_sid",
            match_fields={
                # Ternary match (value, mask)
                "hdr.ipv6.dst_addr": (SWITCH1_IPV6, IPV6_MASK_ALL)
            },
            action_name="FabricIngress.srv6_end",
            priority=DEFAULT_PRIORITY
        ))

        # Insert ECMP group with only one member (next_hop_mac)
        self.insert(self.helper.build_act_prof_group(
            act_prof_name="FabricIngress.ecmp_selector",
            group_id=1,
            actions=[
                # List of tuples (action name, action param dict)
                ("FabricIngress.set_l2_next_hop", {"dmac": next_hop_mac}),
            ]
        ))

        # Map pkt's IPv6 dst addr to group
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l3_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (sid_list[0], 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Ternary match.
                "hdr.ethernet.dst_addr": next_hop_mac
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()
        # Route MAC addresses
        pkt_route(exp_pkt, next_hop_mac)
        # Decrement TTL...
        pkt_decrement_ttl(exp_pkt)

        # FIXME: the P4 pipeline should calculate correct checksum
        if TCP in pkt:
            pkt[TCP].chksum = 1
            exp_pkt[TCP].chksum = 1
        if UDP in pkt:
            pkt[UDP].chksum = 1
            exp_pkt[UDP].chksum = 1
        if ICMPv6Unknown in exp_pkt:
            pkt[ICMPv6Unknown].cksum = 1
            exp_pkt[ICMPv6Unknown].cksum = 1

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)


@group("srv6")
class FabricSrv6EndTest(P4RuntimeTest):
    """Tests SRv6 end behavior"""

    def buildSrv6Pkt(self, pkt, sid_list):
        sid_len = len(sid_list)
        # Build srv6 packet from the given one...
        srv6_pkt = pkt.copy()
        # Route MAC addresses
        pkt_route(srv6_pkt, SWITCH1_MAC)
        # Set IPv6 dst to first SID...
        srv6_pkt[IPv6].dst = SWITCH1_IPV6
        # Insert SRv6 header between IPv6 header and payload
        srv6_hdr = IPv6ExtHdrSegmentRouting(
            nh=pkt[IPv6].nh,
            addresses=sid_list[::-1],
            len=sid_len * 2,
            segleft=sid_len,
            lastentry=sid_len - 1)
        srv6_pkt[IPv6].nh = 43  # next header is SR header
        srv6_pkt[IPv6].payload = srv6_hdr / pkt[IPv6].payload
        return srv6_pkt

    def runTest(self):
        sid_lists = (
            [SWITCH2_IPV6, SWITCH3_IPV6, HOST2_IPV6],
            [SWITCH2_IPV6, HOST2_IPV6],
        )
        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print "Testing %s packet with %d segments ..." % (
                    pkt_type, len(sid_list))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                pkt = self.buildSrv6Pkt(pkt, sid_list)
                self.testPacket(pkt, sid_list)

    @autocleanup
    def testPacket(self, pkt, sid_list):
        # l2_my_station -> srv6_my_sid -> l3_table -> l2_exact_table
        # No changes to SRH header
        next_hop_mac = SWITCH2_MAC

        # Consider pkt's mac dst addr as my station address
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_my_station",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.srv6_my_sid",
            match_fields={
                # Ternary match (value, mask)
                "hdr.ipv6.dst_addr": (SWITCH1_IPV6, IPV6_MASK_ALL)
            },
            action_name="FabricIngress.srv6_end",
            priority=DEFAULT_PRIORITY
        ))

        # Insert ECMP group with only one member (next_hop_mac)
        self.insert(self.helper.build_act_prof_group(
            act_prof_name="FabricIngress.ecmp_selector",
            group_id=1,
            actions=[
                # List of tuples (action name, action param dict)
                ("FabricIngress.set_l2_next_hop", {"dmac": next_hop_mac}),
            ]
        ))

        # Map pkt's IPv6 dst addr to group
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l3_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (sid_list[0], 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Ternary match.
                "hdr.ethernet.dst_addr": next_hop_mac
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()
        # Route MAC addresses
        pkt_route(exp_pkt, next_hop_mac)
        # Set IPv6 dst to first SID...
        exp_pkt[IPv6].dst = sid_list[0]
        # Decrement TTL...
        pkt_decrement_ttl(exp_pkt)
        # Insert SRv6 header between IPv6 header and payload
        exp_pkt[IPv6ExtHdrSegmentRouting].segleft = exp_pkt[IPv6ExtHdrSegmentRouting].segleft - 1

        # FIXME: the P4 pipeline should calculate correct checksum
        if TCP in pkt:
            pkt[TCP].chksum = 1
            exp_pkt[TCP].chksum = 1
        if UDP in pkt:
            pkt[UDP].chksum = 1
            exp_pkt[UDP].chksum = 1
        if ICMPv6Unknown in exp_pkt:
            pkt[ICMPv6Unknown].cksum = 1
            exp_pkt[ICMPv6Unknown].cksum = 1

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)


@group("srv6")
class FabricSrv6EndPspTest(P4RuntimeTest):
    """Tests SRv6 end PSP behavior"""

    def buildSrv6Pkt(self, pkt, sid_list):
        sid_len = len(sid_list)
        # Build srv6 packet from the given one...
        srv6_pkt = pkt.copy()
        # Route MAC addresses
        pkt_route(srv6_pkt, SWITCH3_MAC)
        # Set IPv6 dst to last SID...
        srv6_pkt[IPv6].dst = SWITCH3_IPV6
        # Insert SRv6 header between IPv6 header and payload
        srv6_hdr = IPv6ExtHdrSegmentRouting(
            nh=pkt[IPv6].nh,
            addresses=sid_list[::-1],
            len=sid_len * 2,
            segleft=1,
            lastentry=sid_len - 1)
        srv6_pkt[IPv6].nh = 43  # next header is SR header
        srv6_pkt[IPv6].payload = srv6_hdr / pkt[IPv6].payload
        return srv6_pkt

    def runTest(self):
        sid_lists = (
            [SWITCH2_IPV6, SWITCH3_IPV6, HOST2_IPV6],
            [SWITCH3_IPV6, HOST2_IPV6],
        )
        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print "Testing %s packet with %d segments ..." % (
                    pkt_type, len(sid_list))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                pkt = self.buildSrv6Pkt(pkt, sid_list)
                self.testPacket(pkt, sid_list)

    @autocleanup
    def testPacket(self, pkt, sid_list):
        # l2_my_station -> srv6_my_sid -> l3_table -> l2_exact_table
        # No changes to SRH header
        next_hop_mac = HOST2_MAC

        # Consider pkt's mac dst addr as my station address
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_my_station",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.srv6_my_sid",
            match_fields={
                # Ternary match (value, mask)
                "hdr.ipv6.dst_addr": (sid_list[-2], IPV6_MASK_ALL)
            },
            action_name="FabricIngress.srv6_end",
            priority=DEFAULT_PRIORITY
        ))

        # Insert ECMP group with only one member (next_hop_mac)
        self.insert(self.helper.build_act_prof_group(
            act_prof_name="FabricIngress.ecmp_selector",
            group_id=1,
            actions=[
                # List of tuples (action name, action param dict)
                ("FabricIngress.set_l2_next_hop", {"dmac": next_hop_mac}),
            ]
        ))

        # Map pkt's IPv6 dst addr to group
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l3_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (sid_list[-1], 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Ternary match.
                "hdr.ethernet.dst_addr": next_hop_mac
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()
        # Route MAC addresses
        pkt_route(exp_pkt, next_hop_mac)
        # Set IPv6 dst to first SID...
        exp_pkt[IPv6].dst = sid_list[-1]
        # Decrement TTL...
        pkt_decrement_ttl(exp_pkt)
        # pop srv6 header
        exp_pkt[IPv6].nh = pkt[IPv6ExtHdrSegmentRouting].nh
        exp_pkt[IPv6].payload = pkt[IPv6ExtHdrSegmentRouting].payload

        # FIXME: the P4 pipeline should calculate correct checksum
        if TCP in pkt:
            pkt[TCP].chksum = 1
            exp_pkt[TCP].chksum = 1
        if UDP in pkt:
            pkt[UDP].chksum = 1
            exp_pkt[UDP].chksum = 1
        if ICMPv6Unknown in exp_pkt:
            pkt[ICMPv6Unknown].cksum = 1
            exp_pkt[ICMPv6Unknown].cksum = 1

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)