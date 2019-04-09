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

#ifndef __DEFINE__
#define __DEFINE__

#define MAX_PORTS 511

#ifndef _BOOL
#define _BOOL bool
#endif
#ifndef _TRUE
#define _TRUE true
#endif
#ifndef _FALSE
#define _FALSE false
#endif

#ifndef _PKT_OUT_HDR_ANNOT
#define _PKT_OUT_HDR_ANNOT
#endif

#ifndef IP_VER_LENGTH
#define IP_VER_LENGTH 4
#endif
#ifndef IP_VERSION_4
#define IP_VERSION_4 4
#endif
#ifndef IP_VERSION_6
#define IP_VERSION_6 6
#endif

#define ETH_HDR_SIZE 14
#define IPV4_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define GTP_HDR_SIZE 8

#define UDP_PORT_GTPU 2152
#define GTP_GPDU 0xff
#define GTPU_VERSION 0x01
#define GTP_PROTOCOL_TYPE_GTP 0x01

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

typedef bit<20> mpls_label_t;
typedef bit<9>  port_num_t;
typedef bit<48> mac_addr_t;
typedef bit<16> group_id_t;
typedef bit<12> vlan_id_t;
typedef bit<48> timestamp_t;
typedef bit<32> switch_id_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> l4_port_t;

const bit<16> ETHERTYPE_QINQ = 0x88A8;
const bit<16> ETHERTYPE_QINQ_NON_STD = 0x9100;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_MPLS = 0x8847;
const bit<16> ETHERTYPE_MPLS_MULTICAST =0x8848;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_ARP  = 0x0806;

const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_ICMPV6 = 58;
const bit<8> PROTO_SRV6 = 123; //FIXME

const bit<4> IPV4_MIN_IHL = 5;

const bit<8> DEFAULT_MPLS_TTL = 64;
const bit<8> DEFAULT_IPV4_TTL = 64;

const bit<8> CPU_MIRROR_SESSION_ID = 250;
const bit<32> REPORT_MIRROR_SESSION_ID = 500;

const bit<4> NPROTO_ETHERNET = 0;
const bit<4> NPROTO_TELEMETRY_DROP_HEADER = 1;
const bit<4> NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER = 2;

const bit<8> ETH_HEADER_LEN = 14;
const bit<8> IPV4_MIN_HEAD_LEN = 20;
const bit<8> UDP_HEADER_LEN = 8;

#endif
