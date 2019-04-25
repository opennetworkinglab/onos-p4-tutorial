# Copyright 2013-present Barefoot Networks, Inc.
# Copyright 2018-present Open Networking Foundation
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

from ptf import testutils as testutils
from ptf.packet import IPv6
from ptf.testutils import group
from scapy.layers.inet6 import *
from scapy.layers.l2 import Ether
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.utils6 import in6_getnsma, in6_getnsmac

from base_test import P4RuntimeTest, autocleanup

# ------------------------------------------------------------------------------
# P4INFO CONSTANTS
#
# Modify to match the content of your P4Info file.
# ------------------------------------------------------------------------------

# Actions
HDR_ETH_DST = "hdr.ethernet.dst_addr"
ACTION_CLONE_TO_CPU = "FabricIngress.clone_to_cpu"

# Tables
TABLE_ACL = "FabricIngress.acl"

# Match fields
HDR_ICMP_TYPE = "fabric_metadata.icmp_type"
HDR_IP_PROTO = "fabric_metadata.ip_proto"
HDR_ETHER_TYPE = "hdr.ethernet.ether_type"

# Controller packet-in/out metadata
PACKET_IN_INGRESS_PORT_META_ID = 1
PACKET_OUT_EGRESS_PORT_META_ID = 1

CPU_CLONE_SESSION_ID = 99

# ------------------------------------------------------------------------------
# TEST CONSTANTS
# ------------------------------------------------------------------------------

DEFAULT_PRIORITY = 10

IPV6_MCAST_MAC_1 = "33:33:00:00:00:01"

SWITCH1_MAC = "00:00:00:00:aa:01"
SWITCH2_MAC = "00:00:00:00:aa:02"
SWITCH3_MAC = "00:00:00:00:aa:03"
HOST1_MAC = "00:00:00:00:00:01"
HOST2_MAC = "00:00:00:00:00:02"

MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"
MAC_FULL_MASK = "FF:FF:FF:FF:FF:FF"
MAC_MULTICAST = "33:33:00:00:00:00"
MAC_MULTICAST_MASK = "FF:FF:00:00:00:00"

SWITCH1_IPV6 = "2001:0:1::1"
SWITCH2_IPV6 = "2001:0:2::1"
SWITCH3_IPV6 = "2001:0:3::1"
HOST1_IPV6 = "2001:0000:85a3::8a2e:370:1111"
HOST2_IPV6 = "2001:0000:85a3::8a2e:370:2222"

ARP_ETH_TYPE = 0x0806
IPV6_ETH_TYPE = 0x86DD

ICMPV6_IP_PROTO = 58
NS_ICMPV6_TYPE = 135
NA_ICMPV6_TYPE = 136


def pkt_mac_swap(pkt):
    orig_dst = pkt[Ether].dst
    pkt[Ether].dst = pkt[Ether].src
    pkt[Ether].src = orig_dst
    return pkt


def pkt_route(pkt, mac_dst):
    pkt[Ether].src = pkt[Ether].dst
    pkt[Ether].dst = mac_dst
    return pkt


def pkt_decrement_ttl(pkt):
    if IP in pkt:
        pkt[IP].ttl -= 1
    elif IPv6 in pkt:
        pkt[IPv6].hlim -= 1
    return pkt


def genNdpNsPkt(src_mac, src_ip, target_ip):
    nsma = in6_getnsma(inet_pton(socket.AF_INET6, target_ip))
    d = inet_ntop(socket.AF_INET6, nsma)
    dm = in6_getnsmac(nsma)
    p = Ether(dst=dm) / IPv6(dst=d, src=src_ip, hlim=255)
    p /= ICMPv6ND_NS(tgt=target_ip)
    p /= ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    return p


def genNdpNaPkt(src_mac, dst_mac, src_ip, dst_ip):
    p = Ether(src=src_mac, dst=dst_mac)
    p /= IPv6(dst=dst_ip, src=src_ip, hlim=255)
    p /= ICMPv6ND_NA(tgt=src_ip)
    p /= ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    return p


# ------------------------------------------------------------------------------
# BASE TEST CLASS
#
# Provides methods to insert table entries and other P4 program-specific
# P4Runtime entities.
# ------------------------------------------------------------------------------


class FabricTest(P4RuntimeTest):

    def __init__(self):
        super(FabricTest, self).__init__()
        self.next_mbr_id = 1
        self.next_grp_id = 1

    def setUp(self):
        super(FabricTest, self).setUp()
        self.port1 = self.swports(1)
        self.port2 = self.swports(2)
        self.port3 = self.swports(3)

    def get_next_mbr_id(self):
        mbr_id = self.next_mbr_id
        self.next_mbr_id = self.next_mbr_id + 1
        return mbr_id

    def get_next_grp_id(self):
        grp_id = self.next_grp_id
        self.next_grp_id = self.next_grp_id + 1
        return grp_id


# ------------------------------------------------------------------------------
# CONTROLLER PACKET-IN/OUT TESTS
#
# To run these tests:
#     make packetio
# ------------------------------------------------------------------------------


@group("packetio")
class PacketOutTest(FabricTest):
    """Tests PacketOut capability."""

    def runPacketOutTest(self, pkt):
        for outport in [self.port1, self.port2]:
            # Forge PacketOut message.
            packet_out_msg = self.helper.build_packet_out(
                payload=str(pkt),
                metadata={
                    "egress_port": outport
                })
            # Send message and expect packet on the given data plane port.
            self.send_packet_out(packet_out_msg)
            testutils.verify_packet(self, pkt, outport)
        # Make sure packet was forwarded only on the specified ports
        testutils.verify_no_other_packets(self)

    def runTest(self):
        print ""
        for t in ["tcp", "udp", "icmp", "arp", "tcpv6", "udpv6", "icmpv6"]:
            print "Testing %s packet..." % t
            pkt = getattr(testutils, "simple_%s_packet" % t)()
            self.runPacketOutTest(pkt)


@group("packetio")
class PacketInTest(FabricTest):
    """Tests PacketIn capability my matching on the packet EtherType"""

    @autocleanup
    def runPacketInTest(self, pkt):
        eth_type = pkt[Ether].type

        self.insert_pre_clone_session(
            session_id=CPU_CLONE_SESSION_ID,
            ports=[self.cpu_port])

        # Match on the given pkt's EtherType.
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.acl",
            match_fields={
                # Ternary match.
                "hdr.ethernet.ether_type": (eth_type, 0xffff)
            },
            action_name="FabricIngress.clone_to_cpu",
            priority=DEFAULT_PRIORITY
        ))

        for inport in [self.port1, self.port2, self.port3]:
            # Send packet and expect PacketIn message, with the given ingress
            # port as part of PacketIn metadata fields.
            testutils.send_packet(self, inport, str(pkt))
            # TODO: make verifying packet_in generic by passing metadata
            self.verify_packet_in(
                exp_pkt=pkt, exp_in_port=inport,
                inport_meta_id=PACKET_IN_INGRESS_PORT_META_ID)

    def runTest(self):
        print ""
        for type in ["tcp", "udp", "icmp", "arp", "tcpv6", "udpv6", "icmpv6"]:
            print "Testing %s packet..." % type
            pkt = getattr(testutils, "simple_%s_packet" % type)()
            self.runPacketInTest(pkt)


# ------------------------------------------------------------------------------
# BRIDGING TESTS
#
# To run these tests:
#     make bridging
# ------------------------------------------------------------------------------


@group("bridging")
class FabricArpNdpRequestWithCloneTest(FabricTest):
    """Tests ability to broadcast ARP requests and NDP Neighbor Solicitation as
    well as cloning to CPU (controller) for host discovery
    """

    @autocleanup
    def test(self, pkt):
        mcast_group_id = 10
        mcast_ports = [self.port1, self.port2, self.port3]

        # Add multicast group.
        self.insert_pre_multicast_group(
            group_id=mcast_group_id,
            ports=mcast_ports)

        # Match eth dst: FF:FF:FF:FF:FF:FF (MAC broadcast for ARP requests)
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_ternary_table",
            match_fields={
                # Ternary match.
                "hdr.ethernet.dst_addr": (
                    "FF:FF:FF:FF:FF:FF",
                    "FF:FF:FF:FF:FF:FF")
            },
            action_name="FabricIngress.set_multicast_group",
            action_params={
                "gid": mcast_group_id
            },
            priority=DEFAULT_PRIORITY
        ))

        # Match eth dst: 33:33:**:**:**:** (IPv6 multicast for NDP requests)
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_ternary_table",
            match_fields={
                # Ternary match.
                "hdr.ethernet.dst_addr": (
                    "33:33:00:00:00:00",
                    "FF:FF:00:00:00:00")
            },
            action_name="FabricIngress.set_multicast_group",
            action_params={
                "gid": mcast_group_id
            },
            priority=DEFAULT_PRIORITY
        ))

        # CPU clone session.
        self.insert_pre_clone_session(
            session_id=CPU_CLONE_SESSION_ID,
            ports=[self.cpu_port])

        # ACL entry to clone ARPs
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.acl",
            match_fields={
                # Ternary match.
                "hdr.ethernet.ether_type": (ARP_ETH_TYPE, 0xffff)
            },
            action_name="FabricIngress.clone_to_cpu",
            priority=DEFAULT_PRIORITY
        ))

        # ACL entry to clone NDP Neighbor Solicitation
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.acl",
            match_fields={
                # Ternary match.
                "hdr.ethernet.ether_type": (IPV6_ETH_TYPE, 0xffff),
                "fabric_metadata.ip_proto": (ICMPV6_IP_PROTO, 0xff),
                "fabric_metadata.icmp_type": (NS_ICMPV6_TYPE, 0xff)
            },
            action_name="FabricIngress.clone_to_cpu",
            priority=DEFAULT_PRIORITY
        ))

        for inport in mcast_ports:
            testutils.send_packet(self, inport, str(pkt))
            # Pkt should be received on CPU...
            self.verify_packet_in(exp_pkt=pkt, exp_in_port=inport,
                                  inport_meta_id=PACKET_IN_INGRESS_PORT_META_ID)
            # ...and on all ports except the ingress one.
            verify_ports = set(mcast_ports)
            verify_ports.discard(inport)
            for port in verify_ports:
                testutils.verify_packet(self, pkt, port)
        testutils.verify_no_other_packets(self)

    @autocleanup
    def runTest(self):
        print ""
        print "Testing ARP request packet..."
        arp_pkt = testutils.simple_arp_packet()
        self.test(arp_pkt)

        print "Testing NDP NS packet..."
        ndp_pkt = genNdpNsPkt(src_mac=HOST1_MAC, src_ip=HOST1_IPV6,
                              target_ip=HOST2_IPV6)
        self.test(ndp_pkt)


@group("bridging")
class FabricArpNdpReplyWithCloneTest(FabricTest):
    """Tests ability to clone ARP/NDP replies as well as unicast forwarding to
    requesting host.
    """

    @autocleanup
    def test(self, pkt):
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Ternary match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        # CPU clone session.
        self.insert_pre_clone_session(
            session_id=CPU_CLONE_SESSION_ID,
            ports=[self.cpu_port])

        # ACL entry to clone ARPs
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.acl",
            match_fields={
                # Ternary match.
                "hdr.ethernet.ether_type": (ARP_ETH_TYPE, 0xffff)
            },
            action_name="FabricIngress.clone_to_cpu",
            priority=DEFAULT_PRIORITY
        ))

        # ACL entry to clone NDP Neighbor Solicitation
        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.acl",
            match_fields={
                # Ternary match.
                "hdr.ethernet.ether_type": (IPV6_ETH_TYPE, 0xffff),
                "fabric_metadata.ip_proto": (ICMPV6_IP_PROTO, 0xff),
                "fabric_metadata.icmp_type": (NA_ICMPV6_TYPE, 0xff)
            },
            action_name="FabricIngress.clone_to_cpu",
            priority=DEFAULT_PRIORITY
        ))

        testutils.send_packet(self, self.port1, str(pkt))

        self.verify_packet_in(exp_pkt=pkt, exp_in_port=self.port1,
                              inport_meta_id=PACKET_IN_INGRESS_PORT_META_ID)
        testutils.verify_packet(self, pkt, self.port2)

    def runTest(self):
        print ""
        print "Testing ARP reply packet..."
        # op=1 request, op=2 relpy
        arp_pkt = testutils.simple_arp_packet(
            eth_src=HOST1_MAC, eth_dst=HOST2_MAC, arp_op=2)
        self.test(arp_pkt)

        print "Testing NDP NA packet..."
        ndp_pkt = genNdpNaPkt(src_mac=HOST1_MAC, dst_mac=HOST2_MAC,
                              src_ip=HOST1_IPV6, dst_ip=HOST2_IPV6)
        self.test(ndp_pkt)


@group("bridging")
class BridgingTest(FabricTest):
    """Tests basic L2 forwarding"""

    @autocleanup
    def runBridgingTest(self, pkt):
        mac_src = pkt[Ether].src
        mac_dst = pkt[Ether].dst

        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Ternary match.
                "hdr.ethernet.dst_addr": mac_dst
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port2
            }
        ))

        self.insert(self.helper.build_table_entry(
            table_name="FabricIngress.l2_exact_table",
            match_fields={
                # Ternary match.
                "hdr.ethernet.dst_addr": mac_src
            },
            action_name="FabricIngress.set_output_port",
            action_params={
                "port_num": self.port1
            }
        ))

        # Test bidirectional forwarding by swapping addresses on the given pkt
        pkt2 = pkt_mac_swap(pkt.copy())

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.send_packet(self, self.port2, str(pkt2))

        testutils.verify_each_packet_on_each_port(
            self, [pkt, pkt2], [self.port2, self.port1])

    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp", "tcpv6", "udpv6", "icmpv6"]:
            print "Testing %s packet..." % pkt_type
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                pktlen=120)
            self.runBridgingTest(pkt)
