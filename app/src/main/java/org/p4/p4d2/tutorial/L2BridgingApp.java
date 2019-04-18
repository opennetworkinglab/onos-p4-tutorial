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

import org.onlab.packet.MacAddress;
import org.onlab.util.SharedScheduledExecutors;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.p4.p4d2.tutorial.common.Srv6DeviceConfig;
import org.p4.p4d2.tutorial.common.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.p4.p4d2.tutorial.AppConstants.APP_PREFIX;
import static org.p4.p4d2.tutorial.AppConstants.CPU_CLONE_SESSION_ID;
import static org.p4.p4d2.tutorial.AppConstants.INITIAL_SETUP_DELAY;

@Component(immediate = true)
public class L2BridgingApp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String APP_NAME = APP_PREFIX + ".l2bridging";

    private static final int DEFAULT_BROADCAST_GROUP_ID = 255;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigService configService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    private final DeviceListener deviceListener = new InternalDeviceListener();
    private final HostListener hostListener = new InternalHostListener();

    private ApplicationId appId;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);
        try {
            Utils.waitUntilPreviousCleanupFinished(appId, deviceService, flowRuleService, groupService);
        } catch (InterruptedException e) {
            log.warn("Get exception when clean up the app {}: {}", appId, e.getMessage());
        }
        // Register listeners to be informed about device and host events.
        deviceService.addListener(deviceListener);
        hostService.addListener(hostListener);
        // Set up any existing device which is configure with the SRv6 pipeconf.
        SharedScheduledExecutors.newTimeout(
                this::setUpAllDevices, INITIAL_SETUP_DELAY, TimeUnit.SECONDS);
        deviceService.getAvailableDevices().forEach(device -> setUpDevice(device.id()));
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);
        // Remove flows and groups installed by this app.
        cleanUpAllDevices();
        log.info("Stopped");
    }

    /**
     * Sets up bridging on all devices known by ONOS and for which this ONOS
     * node instance is currently master.
     */
    private void setUpAllDevices() {
        deviceService.getAvailableDevices().forEach(device -> {
            if (mastershipService.isLocalMaster(device.id())) {
                setUpDevice(device.id());
                hostService.getConnectedHosts(device.id()).forEach(host -> {
                    learnHost(host, host.location().deviceId(), host.location().port());
                });
            }
        });
    }

    /**
     * Cleans up L2 bridging runtime configuration from all devices known by
     * ONOS and for which this ONOS node instance is currently master.
     */
    private void cleanUpAllDevices() {
        deviceService.getDevices().forEach(device -> {
            if (mastershipService.isLocalMaster(device.id())) {
                cleanUpDevice(device.id());
            }
        });
    }

    /**
     * Sets up everything necessary to support L2 bridging on the given device.
     *
     * @param deviceId the device to set up
     */
    private void setUpDevice(DeviceId deviceId) {
        // We need a clone group on all switches to clone LLDP  packets for link
        // discovery as well as ARP/NDP ones for host discovery.
        insertCpuCloneGroup(deviceId);

        if (isSpine(deviceId)) {
            // Nothing to do. We support bridging only on leaf/tor switches.
            return;
        }
        insertMulticastGroup(deviceId);
        insertMulticastFlowRules(deviceId);
    }

    /**
     * Cleans up the L2 bridging runtime configuration from the given device.
     *
     * @param deviceId the device to clean up
     */
    private void cleanUpDevice(DeviceId deviceId) {
        log.info("Cleaning up L2 bridging on {}...", deviceId);
        // Remove all runtime entities installed by this app.
        flowRuleService.removeFlowRulesById(appId);
        groupService.getGroups(deviceId, appId).forEach(
                group -> groupService.removeGroup(deviceId, group.appCookie(), appId));
    }

    /**
     * Insert flow rules to perform packet replication via multicast groups for
     * all packets matching ethernet destination broadcast/multicast addresses
     * (e.g. ARP requests, NDP Neighbor Solicitation, etc.)
     *
     * @param deviceId device ID where to install the rules
     */
    private void insertMulticastFlowRules(DeviceId deviceId) {
        log.info("Inserting L2 multicast flow rules on {}...", deviceId);

        // Action: set multicast group id
        final PiAction setMcastGroupAction = PiAction.builder()
                .withId(PiActionId.of("FabricIngress.set_multicast_group"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("gid"),
                        DEFAULT_BROADCAST_GROUP_ID))
                .build();

        // Arp Request - Match exactly FF:FF:FF:FF:FF
        final PiCriterion macBroadcastCriterion = PiCriterion.builder()
                .matchTernary(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        MacAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes(),
                        MacAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes())
                .build();

        // NDP - Match ternary 33:33:**:**:**:**
        final PiCriterion ipv6MulticastCriterion = PiCriterion.builder()
                .matchTernary(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        MacAddress.valueOf("33:33:00:00:00:00").toBytes(),
                        MacAddress.valueOf("FF:FF:00:00:00:00").toBytes())
                .build();

        final String tableId = "FabricIngress.l2_ternary_table";

        final FlowRule rule1 = Utils.forgeFlowRule(
                deviceId, appId, tableId,
                macBroadcastCriterion, setMcastGroupAction);
        final FlowRule rule2 = Utils.forgeFlowRule(
                deviceId, appId, tableId,
                ipv6MulticastCriterion, setMcastGroupAction);

        flowRuleService.applyFlowRules(rule1, rule2);
    }

    /**
     * Insert flow rules to forward packets to a given host located at the given
     * device and port.
     *
     * @param host     host object
     * @param deviceId device where the host is located
     * @param port     port where the host is attached to
     */
    private void learnHost(Host host, DeviceId deviceId, PortNumber port) {

        log.info("Adding L2 bridging rule on {} for host {} (port {})...",
                 deviceId, host.id(), port);

        // Match exactly on the host MAC address.
        final PiCriterion hostMacCriterion = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        host.mac().toBytes())
                .build();

        // Action: L2 unicast (set output port)
        final PiAction l2UnicastAction = PiAction.builder()
                .withId(PiActionId.of("FabricIngress.set_output_port"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("port_num"),
                        port.toLong()))
                .build();

        final FlowRule rule = Utils.forgeFlowRule(
                deviceId, appId, "FabricIngress.l2_exact_table",
                hostMacCriterion, l2UnicastAction);

        flowRuleService.applyFlowRules(rule);
    }

    /**
     * Inserts an ALL group in the ONOS core to replicate packets on all host
     * facing ports. ALL groups in ONOS are equivalent to P4Runtime Packet
     * Replication Engine (PRE) Multicast groups.
     *
     * @param deviceId the device where to install the group
     */
    private void insertMulticastGroup(DeviceId deviceId) {
        Set<PortNumber> ports = getHostFacingPorts(deviceId);

        if (ports.isEmpty()) {
            log.warn("Device {} has 0 host facing ports", deviceId);
            return;
        }

        log.info("Creating multicast group with {} ports on {}",
                 ports.size(), deviceId);

        final GroupDescription multicastGroup = Utils.forgeMulticastGroup(
                appId, deviceId, DEFAULT_BROADCAST_GROUP_ID, ports);

        groupService.addGroup(multicastGroup);
    }

    /**
     * Returns a set of ports for the given device that are used to connect
     * hosts to the fabric.
     *
     * @param deviceId device ID
     * @return set of host facing ports
     */
    private Set<PortNumber> getHostFacingPorts(DeviceId deviceId) {
        // Get all interfaces configured via netcfg for the given device ID and
        // return the corresponding device port number.
        return interfaceService.getInterfaces().stream()
                .map(Interface::connectPoint)
                .filter(cp -> cp.deviceId().equals(deviceId))
                .map(ConnectPoint::port)
                .collect(Collectors.toSet());
    }

    /**
     * Returns true if the given device is defined as a spine in the netcfg.
     *
     * @param deviceId device ID
     * @return true if spine, false otherwise
     */
    private boolean isSpine(DeviceId deviceId) {
        final Srv6DeviceConfig cfg = configService.getConfig(deviceId, Srv6DeviceConfig.class);
        return cfg != null && cfg.isSpine();
    }

    /**
     * Inserts a CLONE group in the ONOS core to clone packets to the CPU (i.e.
     * to ONOS via packet-in). CLONE groups in ONOS are equivalent to P4Runtime
     * Packet Replication Engine (PRE) clone sessions.
     *
     * @param deviceId device where to install the clone session
     */
    private void insertCpuCloneGroup(DeviceId deviceId) {
        log.info("Inserting CPU clone session on {}", deviceId);

        Set<PortNumber> clonePorts = Collections.singleton(PortNumber.CONTROLLER);
        final GroupDescription cloneGroup = Utils.forgeCloneGroup(
                appId, deviceId, CPU_CLONE_SESSION_ID, clonePorts);

        groupService.addGroup(cloneGroup);
    }

    /**
     * Listener of device events.
     */
    public class InternalDeviceListener implements DeviceListener {

        @Override
        public void event(DeviceEvent event) {
            final DeviceId deviceId = event.subject().id();

            switch (event.type()) {
                case DEVICE_ADDED:
                case DEVICE_AVAILABILITY_CHANGED:
                    if (deviceService.isAvailable(deviceId)) {
                        setUpDevice(deviceId);
                    }
                    break;
                case DEVICE_REMOVED:
                    cleanUpDevice(deviceId);
                    break;
                default:
                    // Ignore other types of events.
            }
        }

        @Override
        public boolean isRelevant(DeviceEvent event) {
            // Process device event only if this controller instance is the master.
            final DeviceId deviceId = event.subject().id();
            return mastershipService.isLocalMaster(deviceId);
        }
    }

    /**
     * Listener of host events.
     */
    public class InternalHostListener implements HostListener {

        @Override
        public boolean isRelevant(HostEvent event) {
            // Process host event only if this controller instance is the master
            // for the device where this host is attached to.
            final Host host = event.subject();
            final DeviceId deviceId = host.location().deviceId();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(HostEvent event) {
            final Host host = event.subject();
            // Device and port where the host is located.
            final DeviceId deviceId = host.location().deviceId();
            final PortNumber port = host.location().port();

            switch (event.type()) {
                case HOST_ADDED:
                    //  If host moved we overwrite the previous table entry.
                    learnHost(host, deviceId, port);
                    break;
                case HOST_MOVED:
                case HOST_REMOVED:
                    // Food for thoughts:
                    // how to support host moved and removed events?
                    log.warn("{} event not supported yet", event.type());
                    break;
                default:
                    // Ignore other types of events.
            }
        }
    }
}
