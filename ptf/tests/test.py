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
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from base_test import P4RuntimeTest, stringify, mac_to_binary, ipv6_to_binary, \
    autocleanup

DEFAULT_PRIORITY = 10

SWITCH_MAC = "00:00:00:00:aa:01"

HOST1_MAC = "00:00:00:00:00:01"
HOST2_MAC = "00:00:00:00:00:02"

HOST1_IPV6 = "2001:0000:85a3::8a2e:370:1111"
HOST2_IPV6 = "2001:0000:85a3::8a2e:370:2222"


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

    def add_l2_unicast_entry(self, eth_dstAddr, out_port):
        out_port_ = stringify(out_port, 2)
        self.add_l2_entry(
            eth_dstAddr,
            ["FabricIngress.l2_unicast_fwd", [("port_num", out_port_)]])

    def add_l2_multicast_entry(self, eth_dstAddr, out_ports):
        grp_id = self.get_next_grp_id()
        grp_id_ = stringify(grp_id, 2)
        self.add_mcast_group(grp_id, out_ports)
        self.add_l2_entry(
            eth_dstAddr,
            ["FabricIngress.l2_multicast_fwd", [("gid", grp_id_)]])

    def add_l2_entry(self, eth_dstAddr, action):
        eth_dstAddr_ = mac_to_binary(eth_dstAddr)
        mk = [self.Exact("hdr.ethernet.dst_addr", eth_dstAddr_)]
        self.send_request_add_entry_to_action(
            "FabricIngress.l2_table", mk, *action)

    def add_l2_my_station_entry(self, eth_dstAddr):
        eth_dstAddr_ = mac_to_binary(eth_dstAddr)
        mk = [self.Exact("hdr.ethernet.dst_addr", eth_dstAddr_)]
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

    def add_acl_cpu_entry(self, eth_type=None, clone=False):
        eth_type_ = stringify(eth_type, 2)
        eth_type_mask = stringify(0xFFFF, 2)
        action_name = "clone_to_cpu" if clone else "punt_to_cpu"
        self.send_request_add_entry_to_action(
            "FabricIngress.acl",
            [self.Ternary("hdr.ethernet.ether_type", eth_type_, eth_type_mask)],
            "FabricIngress." + action_name, [],
            DEFAULT_PRIORITY)

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


class FabricBridgingTest(FabricTest):

    @autocleanup
    def runBridgingTest(self, pkt):
        mac_src = pkt[Ether].src
        mac_dst = pkt[Ether].dst
        # miss on filtering.fwd_classifier => bridging
        self.add_l2_unicast_entry(mac_dst, self.port2)
        self.add_l2_unicast_entry(mac_src, self.port1)
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


class FabricIPv6UnicastTest(FabricTest):

    @autocleanup
    def doRunTest(self, pkt, next_hop_mac, prefix_len=128):
        if IPv6 not in pkt or Ether not in pkt:
            self.fail("Cannot do IPv6 test with packet that is not IPv6")
        self.add_l2_my_station_entry(pkt[Ether].dst)
        self.add_l3_ecmp_entry(pkt[IPv6].dst, prefix_len, [next_hop_mac])
        self.add_l2_unicast_entry(next_hop_mac, self.port2)
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
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ipv6_src=HOST1_IPV6, ipv6_dst=HOST2_IPV6
            )
            self.doRunTest(pkt, HOST2_MAC)


@group("packetio")
class FabricPacketOutTest(FabricTest):

    def runPacketOutTest(self, pkt):
        for port in [self.port1, self.port2]:
            port_hex = stringify(port, 2)
            packet_out = p4runtime_pb2.PacketOut()
            packet_out.payload = str(pkt)
            egress_physical_port = packet_out.metadata.add()
            egress_physical_port.metadata_id = 1
            egress_physical_port.value = port_hex

            self.send_packet_out(packet_out)
            testutils.verify_packet(self, pkt, port)
        testutils.verify_no_other_packets(self)

    @autocleanup
    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp", "arp", "tcpv6", "udpv6",
                         "icmpv6"]:
            print "Testing %s packet..." % pkt_type
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
            self.runPacketOutTest(pkt)


@group("packetio")
class FabricPacketInTest(FabricTest):

    @autocleanup
    def runPacketInTest(self, pkt, eth_type=None):
        if eth_type is None:
            eth_type = pkt[Ether].type
        self.add_acl_cpu_entry(eth_type=eth_type)
        for port in [self.port1, self.port2, self.port3]:
            testutils.send_packet(self, port, str(pkt))
            self.verify_packet_in(pkt, port)
        testutils.verify_no_other_packets(self)

    def runTest(self):
        print ""
        for pkt_type in ["tcp", "udp", "icmp", "arp", "tcpv6", "udpv6",
                         "icmpv6"]:
            print "Testing %s packet..." % pkt_type
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
            self.runPacketInTest(pkt)


class FabricArpBroadcastWithCloneTest(FabricTest):

    @autocleanup
    def runTest(self):
        ports = [self.port1, self.port2, self.port3]
        pkt = testutils.simple_arp_packet()
        # FIXME: use clone session APIs when supported on PI
        # For now we add the CPU port to the mc group.
        self.add_l2_multicast_entry(pkt[Ether].dst, ports + [self.cpu_port])
        self.add_acl_cpu_entry(eth_type=pkt[Ether].type, clone=True)

        for inport in ports:
            testutils.send_packet(self, inport, str(pkt))
            # Pkt should be received on CPU and on all ports
            # except the ingress one.
            self.verify_packet_in(exp_pkt=pkt, exp_in_port=inport)
            verify_ports = set(ports)
            verify_ports.discard(inport)
            for port in verify_ports:
                testutils.verify_packet(self, pkt, port)
        testutils.verify_no_other_packets(self)
