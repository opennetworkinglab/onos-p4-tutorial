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

# ------------------------------------------------------------------------------
# BRIDGING TESTS
#
# To run all tests:
#     make bridging
# ------------------------------------------------------------------------------

from ptf.testutils import group

from base_test import *

# ------------------------------------------------------------------------------
# P4INFO CONSTANTS
#
# Modify to match the content of your P4Info file.
# ------------------------------------------------------------------------------

CPU_CLONE_SESSION_ID = 99
PACKET_IN_INGRESS_PORT_META_ID = 1


@group("bridging")
class FabricArpNdpRequestWithCloneTest(P4RuntimeTest):
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
class FabricArpNdpReplyWithCloneTest(P4RuntimeTest):
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
class BridgingTest(P4RuntimeTest):
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
