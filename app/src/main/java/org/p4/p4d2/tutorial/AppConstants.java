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

import com.google.common.collect.ImmutableMap;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.pi.model.PiPipeconfId;

import java.util.Map;

public class AppConstants {

    public static final String APP_PREFIX = "org.p4.srv6-tutorial";
    public static final PiPipeconfId PIPECONF_ID = new PiPipeconfId("org.p4.srv6-tutorial");

    // From the P4Info file. Needed for mapping flow rules and flow objectives
    // in the interpreter and pipeliner.
    public static final String ACL_TABLE = "FabricIngress.acl";
    public static final String DROP_ACTION = "FabricIngress.drop";
    public static final String CLONE_TO_CPU = "FabricIngress.clone_to_cpu";
    public static final String NO_ACTION = "NoAction";

    public static final String INGRESS_PORT_CTRL_METADATA = "ingress_port";
    public static final String EGRESS_PORT_CTRL_METADATA = "egress_port";

    public static final Map<Criterion.Type, String> CRITERION_MAP =
            new ImmutableMap.Builder<Criterion.Type, String>()
                    .put(Criterion.Type.IN_PORT, "standard_metadata.ingress_port")
                    .put(Criterion.Type.ETH_DST, "hdr.ethernet.dst_addr")
                    .put(Criterion.Type.ETH_SRC, "hdr.ethernet.src_addr")
                    .put(Criterion.Type.ETH_TYPE, "hdr.ethernet.ether_type")
                    .put(Criterion.Type.IPV6_DST, "hdr.ipv6.dst_addr")
                    .put(Criterion.Type.IP_PROTO, "fabric_metadata.ip_proto")
                    .put(Criterion.Type.ICMPV4_TYPE, "fabric_metadata.icmp_type")
                    .put(Criterion.Type.ICMPV6_TYPE, "fabric_metadata.icmp_type")
                    .build();

    public static final int DEFAULT_FLOW_RULE_PRIORITY = 10;
    public static final int INITIAL_SETUP_DELAY = 5; // Seconds.
    public static final int CLEAN_UP_DELAY = 2000; // milliseconds
    public static final int DEFAULT_CLEAN_UP_RETRY_TIMES = 10;

    public static final int CPU_PORT_ID = 255;
    public static final int CPU_CLONE_SESSION_ID = 99;
}
