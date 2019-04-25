# Copyright 201-present Open Networking Foundation
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
# CONTROLLER PACKET-IN/OUT TESTS
#
# To run all tests:
#     make packetio
# ------------------------------------------------------------------------------

from ptf.testutils import group

from base_test import *

# ------------------------------------------------------------------------------
# P4INFO CONSTANTS
#
# Modify to match the content of your P4Info file.
# ------------------------------------------------------------------------------

CPU_CLONE_SESSION_ID = 99


@group("packetio")
class PacketOutTest(P4RuntimeTest):
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
        for t in ["tcp", "udp", "icmp", "arp", "tcpv6", "udpv6", "icmpv6"]:
            print_inline("%s ... " % t)
            pkt = getattr(testutils, "simple_%s_packet" % t)()
            self.runPacketOutTest(pkt)


@group("packetio")
class PacketInTest(P4RuntimeTest):
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
        for type in ["tcp", "udp", "icmp", "arp", "tcpv6", "udpv6", "icmpv6"]:
            print_inline("%s ... " % type)
            pkt = getattr(testutils, "simple_%s_packet" % type)()
            self.runPacketInTest(pkt)
