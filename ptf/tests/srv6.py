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


def insert_srv6_header(pkt, sid_list):
    """Applies SRv6 insert transformation to the given packet.
    """
    # Set IPv6 dst to first SID...
    pkt[IPv6].dst = sid_list[0]
    # Insert SRv6 header between IPv6 header and payload
    sid_len = len(sid_list)
    srv6_hdr = IPv6ExtHdrSegmentRouting(
        nh=pkt[IPv6].nh,
        addresses=sid_list[::-1],
        len=sid_len * 2,
        segleft=sid_len - 1,
        lastentry=sid_len - 1)
    pkt[IPv6].nh = 43  # next IPv6 header is SR header
    pkt[IPv6].payload = srv6_hdr / pkt[IPv6].payload
    return pkt


def pop_srv6_header(pkt):
    """Removes SRv6 header from the given packet.
    """
    pkt[IPv6].nh = pkt[IPv6ExtHdrSegmentRouting].nh
    pkt[IPv6].payload = pkt[IPv6ExtHdrSegmentRouting].payload


def set_cksum(pkt, cksum):
    if TCP in pkt:
        pkt[TCP].chksum = cksum
    if UDP in pkt:
        pkt[UDP].chksum = cksum
    if ICMPv6Unknown in pkt:
        pkt[ICMPv6Unknown].cksum = cksum


@group("srv6")
class Srv6InsertTest(P4RuntimeTest):
    """Tests SRv6 insert behavior, where the switch receives an IPv6 packet and
    inserts the SRv6 header
    """

    def runTest(self):
        sid_lists = (
            [SWITCH2_IPV6, SWITCH3_IPV6, HOST2_IPV6],
            [SWITCH2_IPV6, HOST2_IPV6],
        )
        next_hop_mac = SWITCH2_MAC

        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print_inline("%s %d SIDs ... " % (pkt_type, len(sid_list)))

                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()

                self.testPacket(pkt, sid_list, next_hop_mac)

    @autocleanup
    def testPacket(self, pkt, sid_list, next_hop_mac):

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

        # Now that we inserted the SRv6 header, we expect the pkt's IPv6 dst
        # addr to be the first on the SID list.
        first_sid = sid_list[0]
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l3_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (first_sid, 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": next_hop_mac
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        # Build expected packet from the given one...
        exp_pkt = insert_srv6_header(pkt.copy(), sid_list)

        # Route and decrement TTL
        pkt_route(exp_pkt, next_hop_mac)
        pkt_decrement_ttl(exp_pkt)

        # FIXME: update P4 program to calculate correct checksum
        set_cksum(pkt, 1)
        set_cksum(exp_pkt, 1)

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)


@group("srv6")
class Srv6TransitTest(P4RuntimeTest):
    """Tests SRv6 transit behavior, where the switch ignores the SRv6 header
    and routes the packet normally, without applying any SRv6-related
    modifications.
    """

    def runTest(self):
        my_sid = SWITCH1_IPV6
        sid_lists = (
            [SWITCH2_IPV6, SWITCH3_IPV6, HOST2_IPV6],
            [SWITCH2_IPV6, HOST2_IPV6],
        )
        next_hop_mac = SWITCH2_MAC

        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print_inline("%s %d SIDs ... " % (pkt_type, len(sid_list)))

                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                pkt = insert_srv6_header(pkt, sid_list)

                self.testPacket(pkt, next_hop_mac, my_sid)

    @autocleanup
    def testPacket(self, pkt, next_hop_mac, my_sid):

        # Consider pkt's mac dst addr as my station address
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_my_station",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        # This should be missed, this is plain IPv6 routing.
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.srv6_my_sid",
            match_fields={
                # Ternary match (value, mask)
                "hdr.ipv6.dst_addr": (my_sid, IPV6_MASK_ALL)
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
                "hdr.ipv6.dst_addr": (pkt[IPv6].dst, 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": next_hop_mac
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()

        # Route and decrement TTL
        pkt_route(exp_pkt, next_hop_mac)
        pkt_decrement_ttl(exp_pkt)

        # FIXME: update P4 program to calculate correct checksum
        set_cksum(pkt, 1)
        set_cksum(exp_pkt, 1)

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)


@group("srv6")
class Srv6EndTest(P4RuntimeTest):
    """Tests SRv6 end behavior (without pop), where the switch forwards the
    packet to the next SID found in the SRv6 header.
    """

    def runTest(self):
        my_sid = SWITCH2_IPV6
        sid_lists = (
            [SWITCH2_IPV6, SWITCH3_IPV6, HOST2_IPV6],
            [SWITCH2_IPV6, SWITCH3_IPV6, SWITCH4_IPV6, HOST2_IPV6],
        )
        next_hop_mac = SWITCH3_MAC

        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print_inline("%s %d SIDs ... " % (pkt_type, len(sid_list)))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()

                pkt = insert_srv6_header(pkt, sid_list)
                self.testPacket(pkt, sid_list, next_hop_mac, my_sid)

    @autocleanup
    def testPacket(self, pkt, sid_list, next_hop_mac, my_sid):

        # Consider pkt's mac dst addr as my station address
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_my_station",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        # This should be matched, we want SRv6 end behavior to be applied.
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.srv6_my_sid",
            match_fields={
                # Ternary match (value, mask)
                "hdr.ipv6.dst_addr": (my_sid, IPV6_MASK_ALL)
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

        # After applying the srv6_end action, we expect to IPv6 dst to be the
        # next SID in the list, we should route based on that.
        next_sid = sid_list[1]
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l3_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (next_sid, 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": next_hop_mac
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()

        # Set IPv6 dst to next SID and decrement segleft...
        exp_pkt[IPv6].dst = next_sid
        exp_pkt[IPv6ExtHdrSegmentRouting].segleft -= 1

        # Route and decrement TTL...
        pkt_route(exp_pkt, next_hop_mac)
        pkt_decrement_ttl(exp_pkt)

        # FIXME: update P4 program to calculate correct checksum
        set_cksum(pkt, 1)
        set_cksum(exp_pkt, 1)

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)


@group("srv6")
class Srv6EndPspTest(P4RuntimeTest):
    """Tests SRv6 end PSP behavior (i.e. with pop), where the switch SID is the
    last one and the switch removes the SRv6  header beofre routing the packet
    to  it's final destination.
    """

    def runTest(self):
        my_sid = SWITCH3_IPV6
        sid_lists = (
            [SWITCH3_IPV6, HOST2_IPV6],
        )
        next_hop_mac = HOST2_MAC

        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print_inline("%s %d SIDs ... " % (pkt_type, len(sid_list)))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                pkt = insert_srv6_header(pkt, sid_list)
                self.testPacket(pkt, sid_list, next_hop_mac, my_sid)

    @autocleanup
    def testPacket(self, pkt, sid_list, next_hop_mac, my_sid):

        # Consider pkt's mac dst addr as my station address
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_my_station",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        # This should be matched, we want SRv6 end behavior to be applied.
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.srv6_my_sid",
            match_fields={
                # Ternary match (value, mask)
                "hdr.ipv6.dst_addr": (my_sid, IPV6_MASK_ALL)
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
        next_sid = sid_list[1]
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l3_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (next_sid, 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": next_hop_mac
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()

        # Expect IPv6 dst to be the next SID...
        exp_pkt[IPv6].dst = next_sid
        # Remove SRv6 header since we are performing PSP.
        pop_srv6_header(exp_pkt)

        # Route and decrement TTL
        pkt_route(exp_pkt, next_hop_mac)
        pkt_decrement_ttl(exp_pkt)

        # FIXME: update P4 program to calculate correct checksum
        set_cksum(pkt, 1)
        set_cksum(exp_pkt, 1)

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)
