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

from p4.v1 import p4runtime_pb2
from ptf import testutils as testutils
from ptf.packet import IPv6
from ptf.testutils import group
from scapy.layers.inet6 import *
from scapy.layers.l2 import Ether
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.utils6 import in6_getnsma, in6_getnsmac

from base_test import P4RuntimeTest, stringify, mac_to_binary, ipv6_to_binary, \
    autocleanup

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

    def add_acl_clone_to_cpu_entry(self, eth_type=None, ip_proto=None,
                                   icmp_type=None):
        """
        Adds a table entry for the ACL table to clone packets to the CPU.
        :param eth_type: Ether type
        :param ip_proto: IPv4/6 next protocol type
        :param icmp_type: ICMP type
        """
        match_key = []
        if eth_type:
            eth_type_ = stringify(eth_type, 2)
            eth_type_mask = stringify(0xFFFF, 2)
            match_key.append(self.Ternary(
                HDR_ETHER_TYPE, eth_type_, eth_type_mask))
        if ip_proto:
            ip_proto_ = stringify(ip_proto, 1)
            ip_proto_mask = stringify(0xFF, 1)
            match_key.append(self.Ternary(
                HDR_IP_PROTO, ip_proto_, ip_proto_mask))
        if icmp_type:
            icmp_type_ = stringify(icmp_type, 1)
            icmp_type_mask = stringify(0xFF, 1)
            match_key.append(self.Ternary(
                HDR_ICMP_TYPE, icmp_type_, icmp_type_mask))

        self.send_request_add_entry_to_action(
            TABLE_ACL, match_key, ACTION_CLONE_TO_CPU, [], DEFAULT_PRIORITY)

    def add_l2_exact_entry(self, eth_dst, out_port):
        out_port_ = stringify(out_port, 2)
        eth_dst_ = mac_to_binary(eth_dst)
        mk = [self.Exact(HDR_ETH_DST, eth_dst_)]
        self.send_request_add_entry_to_action(
            "FabricIngress.l2_exact_table", mk,
            "FabricIngress.set_output_port", [("port_num", out_port_)])

    def add_l2_ternary_entry(self, eth_dst, eth_dst_mask, mcast_group_id):
        mc_group_id_ = stringify(mcast_group_id, 2)
        eth_dst_ = mac_to_binary(eth_dst)
        eth_dst_mask_ = mac_to_binary(eth_dst_mask)
        mk = [self.Ternary(HDR_ETH_DST, eth_dst_, eth_dst_mask_)]
        self.send_request_add_entry_to_action(
            "FabricIngress.l2_ternary_table", mk,
            "FabricIngress.set_multicast_group", [("gid", mc_group_id_)],
            DEFAULT_PRIORITY)

    def add_l2_my_station_entry(self, eth_dst):
        eth_dst_ = mac_to_binary(eth_dst)
        mk = [self.Exact(HDR_ETH_DST, eth_dst_)]
        self.send_request_add_entry_to_action(
            "FabricIngress.l2_my_station", mk, "NoAction", [])

    def add_l3_entry(self, dstAddr, prefix_len, grp_id):
        dstAddr_ = ipv6_to_binary(dstAddr)
        self.send_request_add_entry_to_group(
            "FabricIngress.l3_table",
            [self.Lpm("hdr.ipv6.dst_addr", dstAddr_, prefix_len)], grp_id)

    # members is list of tuples (action_name, params)
    # params contains a tuple for each param (param_name, param_value)
    def add_l3_group_with_members(self, grp_id, members):
        mbr_ids = []
        for member in members:
            mbr_id = self.get_next_mbr_id()
            mbr_ids.append(mbr_id)
            self.send_request_add_member("FabricIngress.ecmp_selector", mbr_id,
                                         *member)
        self.send_request_add_group("FabricIngress.ecmp_selector", grp_id,
                                    grp_size=len(mbr_ids), mbr_ids=mbr_ids)

    def add_l3_ecmp_entry(self, dstAddr, prefix_len, next_hop_macs):
        members = []
        for mac in next_hop_macs:
            mac_ = mac_to_binary(mac)
            members.append(("FabricIngress.set_l2_next_hop", [("dmac", mac_)]))
        grp_id = self.get_next_grp_id()
        self.add_l3_group_with_members(grp_id, members)
        self.add_l3_entry(dstAddr, prefix_len, grp_id)

    def add_mcast_group(self, group_id, ports):
        req = self.get_new_write_request()
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        pre_entry = update.entity.packet_replication_engine_entry
        mg_entry = pre_entry.multicast_group_entry
        mg_entry.multicast_group_id = group_id
        for port in ports:
            replica = mg_entry.replicas.add()
            replica.egress_port = port
            replica.instance = 0
        return req, self.write_request(req)

    def add_clone_session(self, session_id, ports, cos=0,
                          packet_length_bytes=0):
        req = self.get_new_write_request()
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        pre_entry = update.entity.packet_replication_engine_entry
        clone_entry = pre_entry.clone_session_entry
        clone_entry.session_id = session_id
        clone_entry.class_of_service = cos
        clone_entry.packet_length_bytes = packet_length_bytes
        for port in ports:
            replica = clone_entry.replicas.add()
            replica.egress_port = port
            replica.instance = 1
        return req, self.write_request(req)

    def add_ndp_reply_entry(self, target_addr, target_mac):
        target_addr = inet_pton(socket.AF_INET6, target_addr)
        target_mac = mac_to_binary(target_mac)
        mk = [self.Exact("hdr.ndp.target_addr", target_addr)]
        self.send_request_add_entry_to_action(
            "FabricIngress.ndp_reply", mk,
            "FabricIngress.ndp_advertisement", [("router_mac", target_mac)])

    def add_srv6_transit_2segment_entry(self, dst_ip, prefix_len, s1_ip, s2_ip):
        self.send_request_add_entry_to_action(
            "FabricIngress.srv6_transit",
            [self.Lpm("hdr.ipv6.dst_addr", ipv6_to_binary(dst_ip), prefix_len)],
            "FabricIngress.srv6_t_insert_2",
            [("s1", ipv6_to_binary(s1_ip)), ("s2", ipv6_to_binary(s2_ip))]
        )

    def add_srv6_transit_3segment_entry(self, dst_ip, prefix_len, s1_ip, s2_ip,
                                        s3_ip):
        self.send_request_add_entry_to_action(
            "FabricIngress.srv6_transit",
            [self.Lpm("hdr.ipv6.dst_addr", ipv6_to_binary(dst_ip), prefix_len)],
            "FabricIngress.srv6_t_insert_3",
            [("s1", ipv6_to_binary(s1_ip)), ("s2", ipv6_to_binary(s2_ip)),
             ("s3", ipv6_to_binary(s3_ip))]
        )

    def add_srv6_my_sid_entry(self, my_sid):
        mask = stringify(0xffffffffffffffffffffffffffffffff, 2)
        self.send_request_add_entry_to_action(
            "FabricIngress.srv6_my_sid",
            [self.Ternary("hdr.ipv6.dst_addr", ipv6_to_binary(my_sid), mask)],
            "FabricIngress.srv6_end",
            [],
            DEFAULT_PRIORITY
        )


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
        for port in [self.port1, self.port2]:
            # Forge PacketOut message.
            packet_out = p4runtime_pb2.PacketOut()
            packet_out.payload = str(pkt)
            egress_physical_port = packet_out.metadata.add()
            # Set egress port metadata.
            egress_physical_port.metadata_id = PACKET_OUT_EGRESS_PORT_META_ID
            # 9 bits hence 2 bytes for port numbers.
            egress_physical_port.value = stringify(port, 2)
            # Send message and expect packet on the given data plane port.
            self.send_packet_out(packet_out)
            testutils.verify_packet(self, pkt, port)
        # Make sure packet was forwarded only on the specified ports
        testutils.verify_no_other_packets(self)

    def runTest(self):
        print ""
        for type in ["tcp", "udp", "icmp", "arp", "tcpv6", "udpv6", "icmpv6"]:
            print "Testing %s packet..." % type
            pkt = getattr(testutils, "simple_%s_packet" % type)()
            self.runPacketOutTest(pkt)


@group("packetio")
class PacketInTest(FabricTest):
    """Tests PacketIn capability my matching on the packet EtherType"""

    @autocleanup
    def runPacketInTest(self, pkt):
        eth_type = pkt[Ether].type
        # Match on the given pkt's EtherType.
        self.add_acl_clone_to_cpu_entry(eth_type=eth_type)
        self.add_clone_session(session_id=CPU_CLONE_SESSION_ID,
                               ports=[self.cpu_port])

        for inport in [self.port1, self.port2, self.port3]:
            # Send packet and expect PacketIn message, with the given ingress
            # port as part of PacketIn metadata fields.
            testutils.send_packet(self, inport, str(pkt))
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
        self.add_mcast_group(group_id=mcast_group_id, ports=mcast_ports)
        # Match eth dst: FF:FF:FF:FF:FF:FF (MAC broadcast for ARP requests)
        self.add_l2_ternary_entry(
            eth_dst="FF:FF:FF:FF:FF:FF",
            eth_dst_mask="FF:FF:FF:FF:FF:FF",
            mcast_group_id=mcast_group_id)
        # Match eth dst: 33:33:**:**:**:** (IPv6 multicast for NDP requests)
        self.add_l2_ternary_entry(
            eth_dst="33:33:00:00:00:00",
            eth_dst_mask="FF:FF:00:00:00:00",
            mcast_group_id=mcast_group_id)

        # Clone ARPs
        self.add_acl_clone_to_cpu_entry(eth_type=ARP_ETH_TYPE)
        # Clone NDP Neighbor Solicitation
        self.add_acl_clone_to_cpu_entry(
            eth_type=IPV6_ETH_TYPE, ip_proto=ICMPV6_IP_PROTO,
            icmp_type=NS_ICMPV6_TYPE)
        self.add_clone_session(CPU_CLONE_SESSION_ID, [self.cpu_port])

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
        self.add_l2_exact_entry(pkt[Ether].dst, self.port1)
        self.add_acl_clone_to_cpu_entry(eth_type=ARP_ETH_TYPE)
        self.add_acl_clone_to_cpu_entry(
            eth_type=IPV6_ETH_TYPE, ip_proto=ICMPV6_IP_PROTO,
            icmp_type=NA_ICMPV6_TYPE)
        self.add_clone_session(CPU_CLONE_SESSION_ID, [self.cpu_port])

        testutils.send_packet(self, self.port2, str(pkt))

        self.verify_packet_in(exp_pkt=pkt, exp_in_port=self.port2,
                              inport_meta_id=PACKET_IN_INGRESS_PORT_META_ID)
        testutils.verify_packet(self, pkt, self.port1)

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
        self.add_l2_exact_entry(mac_dst, self.port2)
        self.add_l2_exact_entry(mac_src, self.port1)
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

# ------------------------------------------------------------------------------
# IPV6 ROUTING TESTS
#
# To run these tests:
#     make routing
# ------------------------------------------------------------------------------


@group("routing")
class FabricNdpReplyGenTest(FabricTest):
    """Tests automatic generation of NDP Neighbor Advertisement for IPV6 address
    associated to the switch interface."""

    @autocleanup
    def runTest(self):
        pkt = genNdpNsPkt(HOST1_MAC, HOST1_IPV6, SWITCH1_IPV6)
        exp_pkt = genNdpNaPkt(SWITCH1_MAC, IPV6_MCAST_MAC_1,
                              SWITCH1_IPV6, HOST1_IPV6)

        self.add_ndp_reply_entry(SWITCH1_IPV6, SWITCH1_MAC)

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port1)

@group("bridging")
class FabricIPv6RoutingTest(FabricTest):
    """Tests basic IPv6 routing"""

    @autocleanup
    def doRunTest(self, pkt, next_hop_mac, prefix_len=128):
        if IPv6 not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv6 test with packet that is not IPv6")

        self.add_l2_my_station_entry(pkt[Ether].dst)
        self.add_l3_ecmp_entry(pkt[IPv6].dst, prefix_len, [next_hop_mac])
        self.add_l2_exact_entry(next_hop_mac, self.port2)

        exp_pkt = pkt.copy()
        pkt_route(exp_pkt, next_hop_mac)
        pkt_decrement_ttl(exp_pkt)

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)

    def runTest(self):
        print ""
        for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
            print "Testing %s packet..." % pkt_type
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=HOST1_MAC, eth_dst=SWITCH1_MAC,
                ipv6_src=HOST1_IPV6, ipv6_dst=HOST2_IPV6
            )
            self.doRunTest(pkt, HOST2_MAC)

# ------------------------------------------------------------------------------
# SRV6 TESTS
#
# To run these tests:
#     make srv6
# ------------------------------------------------------------------------------


@group("srv6")
class FabricSrv6InsertTest(FabricTest):
    """Tests SRv6 insert behavior"""

    @autocleanup
    def doRunTest(self, pkt, sid_list):
        if IPv6 not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv6 test with packet that is not IPv6")
        # l2_my_station -> srv6_transit -> l3_table -> l2_exact_table
        self.add_l2_my_station_entry(SWITCH1_MAC)
        sid_len = len(sid_list)
        getattr(self, "add_srv6_transit_%dsegment_entry" % sid_len)(
            pkt[IPv6].dst, 128, *sid_list)
        self.add_l3_ecmp_entry(sid_list[0], 128, [SWITCH2_MAC])
        self.add_l2_exact_entry(SWITCH2_MAC, self.port2)

        exp_pkt = Ether(src=SWITCH1_MAC, dst=SWITCH2_MAC)
        exp_pkt /= IPv6(dst=sid_list[0], src=pkt[IPv6].src, hlim=63)
        exp_pkt /= IPv6ExtHdrSegmentRouting(nh=pkt[IPv6].nh,
                                            addresses=sid_list[::-1],
                                            len=sid_len * 2,
                                            segleft=sid_len - 1,
                                            lastentry=sid_len - 1)
        exp_pkt /= pkt[IPv6].payload

        if ICMPv6EchoRequest in exp_pkt:
            # FIXME: the P4 pipeline should calculate correct ICMPv6 checksum
            exp_pkt[ICMPv6EchoRequest].cksum = pkt[ICMPv6EchoRequest].cksum

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)

    def runTest(self):
        sid_lists = (
            [SWITCH2_IPV6, SWITCH3_IPV6, HOST2_IPV6],
            [SWITCH3_IPV6, HOST2_IPV6],
        )
        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print "Testing %s packet with %d segments ..." % (
                    pkt_type, len(sid_list))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC, eth_dst=SWITCH1_MAC,
                    ipv6_src=HOST1_IPV6, ipv6_dst=HOST2_IPV6
                )
                self.doRunTest(pkt, sid_list)


@group("srv6")
class FabricSrv6TransitTest(FabricTest):
    """Tests SRv6 transit behavior"""

    @autocleanup
    def doRunTest(self, pkt):
        if IPv6 not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv6 test with packet that is not IPv6")

        # l2_my_station -> l3_table -> l2_exact_table
        # No changes to SRH header
        self.add_l2_my_station_entry(SWITCH2_MAC)
        self.add_srv6_my_sid_entry(SWITCH2_IPV6)
        self.add_l3_ecmp_entry(SWITCH3_IPV6, 128, [SWITCH3_MAC])
        self.add_l2_exact_entry(SWITCH3_MAC, self.port2)

        testutils.send_packet(self, self.port1, str(pkt))

        exp_pkt = Ether(src=SWITCH2_MAC, dst=SWITCH3_MAC)
        exp_pkt /= IPv6(dst=SWITCH3_IPV6, src=pkt[IPv6].src, hlim=63)
        exp_pkt /= IPv6ExtHdrSegmentRouting(
            nh=pkt[IPv6ExtHdrSegmentRouting].nh,
            addresses=[HOST2_IPV6, SWITCH3_IPV6],
            len=2 * 2, segleft=1, lastentry=1)
        exp_pkt /= pkt[IPv6ExtHdrSegmentRouting].payload

        testutils.verify_packet(self, exp_pkt, self.port2)

    def runTest(self):
        pkt = Ether(src=SWITCH1_MAC, dst=SWITCH2_MAC)
        pkt /= IPv6(dst=SWITCH3_IPV6, src=HOST1_IPV6, hlim=64)
        pkt /= IPv6ExtHdrSegmentRouting(nh=6,
                                        addresses=[HOST2_IPV6, SWITCH3_IPV6],
                                        len=2 * 2, segleft=1, lastentry=1)
        pkt /= TCP()

        self.doRunTest(pkt)


@group("srv6")
class FabricSrv6EndTest(FabricTest):
    """Tests SRv6 end behavior"""

    @autocleanup
    def doRunTest(self, pkt):
        if IPv6 not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv6 test with packet that is not IPv6")

        # l2_my_station -> my_sid -> l3_table -> l2_exact_table
        # Decrement SRH SL (after transform SL > 0)
        self.add_l2_my_station_entry(SWITCH2_MAC)
        self.add_srv6_my_sid_entry(SWITCH2_IPV6)
        self.add_l3_ecmp_entry(SWITCH3_IPV6, 128, [SWITCH3_MAC])
        self.add_l2_exact_entry(SWITCH3_MAC, self.port2)

        testutils.send_packet(self, self.port1, str(pkt))

        exp_pkt = Ether(src=SWITCH2_MAC, dst=SWITCH3_MAC)
        exp_pkt /= IPv6(dst=SWITCH3_IPV6, src=pkt[IPv6].src, hlim=63)
        exp_pkt /= IPv6ExtHdrSegmentRouting(
            nh=pkt[IPv6ExtHdrSegmentRouting].nh,
            addresses=[HOST2_IPV6, SWITCH3_IPV6, SWITCH2_IPV6],
            len=3 * 2, segleft=1, lastentry=2)
        exp_pkt /= pkt[IPv6ExtHdrSegmentRouting].payload

        testutils.verify_packet(self, exp_pkt, self.port2)

    def runTest(self):
        pkt = Ether(src=SWITCH1_MAC, dst=SWITCH2_MAC)
        pkt /= IPv6(dst=SWITCH2_IPV6, src=HOST1_IPV6, hlim=64)
        pkt /= IPv6ExtHdrSegmentRouting(
            nh=6, addresses=[HOST2_IPV6, SWITCH3_IPV6, SWITCH2_IPV6],
            len=3 * 2, segleft=2, lastentry=2)
        pkt /= TCP()

        self.doRunTest(pkt)


@group("srv6")
class FabricSrv6EndPspTest(FabricTest):
    """Tests SRv6 end PSP behavior"""

    @autocleanup
    def doRunTest(self, pkt):
        if IPv6 not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv6 test with packet that is not IPv6")

        # l2_my_station -> my_sid -> l3_table -> l2_exact_table
        # Decrement SRH SL (after transform SL == 0)
        self.add_l2_my_station_entry(SWITCH3_MAC)
        self.add_srv6_my_sid_entry(SWITCH3_IPV6)
        self.add_l3_ecmp_entry(HOST2_IPV6, 128, [HOST2_MAC])
        self.add_l2_exact_entry(HOST2_MAC, self.port2)

        testutils.send_packet(self, self.port1, str(pkt))

        exp_pkt = Ether(src=SWITCH3_MAC, dst=HOST2_MAC)
        exp_pkt /= IPv6(dst=HOST2_IPV6, src=pkt[IPv6].src, hlim=63,
                        nh=pkt[IPv6ExtHdrSegmentRouting].nh)
        exp_pkt /= pkt[IPv6ExtHdrSegmentRouting].payload

        testutils.verify_packet(self, exp_pkt, self.port2)

    def runTest(self):
        pkt = Ether(src=SWITCH2_MAC, dst=SWITCH3_MAC)
        pkt /= IPv6(dst=SWITCH3_IPV6, src=HOST1_IPV6, hlim=64)
        pkt /= IPv6ExtHdrSegmentRouting(
            nh=6, addresses=[HOST2_IPV6, SWITCH3_IPV6, SWITCH2_IPV6],
            len=3 * 2, segleft=1, lastentry=2)
        pkt /= TCP()

        self.doRunTest(pkt)
