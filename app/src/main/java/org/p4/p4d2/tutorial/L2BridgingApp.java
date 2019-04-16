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
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
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
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiCloneSessionEntry;
import org.onosproject.net.pi.runtime.PiCloneSessionEntryHandle;
import org.onosproject.net.pi.runtime.PiPreReplica;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.p4runtime.api.P4RuntimeClient;
import org.onosproject.p4runtime.api.P4RuntimeController;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.p4.p4d2.tutorial.common.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.p4.p4d2.tutorial.AppConstants.APP_PREFIX;
import static org.p4.p4d2.tutorial.AppConstants.CPU_CLONE_SESSION_ID;
import static org.p4.p4d2.tutorial.AppConstants.CPU_PORT_ID;
import static org.p4.p4d2.tutorial.AppConstants.INITIAL_SETUP_DELAY;
import static org.p4.p4d2.tutorial.AppConstants.P4RUNTIME_DEVICE_ID;

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
    private PiPipeconfService pipeconfService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private P4RuntimeController p4RuntimeController;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    private final DeviceListener deviceListener = new InternalDeviceListener();
    private final HostListener hostListener = new InternalHostListener();

    private ApplicationId appId;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);
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
        log.info("Setting up L2 bridging on {}...", deviceId);

        insertMulticastGroup(deviceId);
        insertCpuCloneSession(deviceId);
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
        deleteCpuCloneSession(deviceId);
    }

    /**
     * Insert flow rules to perform packet replication via multicast groups for
     * all packets matching ethernet destination broadcast/multicast addresses
     * (e.g. ARP requests, NDP Neighbor Solicitation, etc.)
     *
     * @param deviceId device ID where to install the rules
     */
    private void insertMulticastFlowRules(DeviceId deviceId) {
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

        final PiTableId l2TernaryTable = PiTableId.of("FabricIngress.l2_ternary_table");

        final FlowRule rule1 = Utils.forgeFlowRule(
                deviceId, appId, l2TernaryTable,
                macBroadcastCriterion, setMcastGroupAction);
        final FlowRule rule2 = Utils.forgeFlowRule(
                deviceId, appId, l2TernaryTable,
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

        final PiTableId l2BroadcastTable = PiTableId.of("FabricIngress.l2_exact_table");

        final FlowRule rule = Utils.forgeFlowRule(
                deviceId, appId, l2BroadcastTable,
                hostMacCriterion, l2UnicastAction);

        flowRuleService.applyFlowRules(rule);
    }

    /**
     * Inserts a BROADCAST group in the ONOS core to replicate packets on all
     * ports known to ONOS for the given device. BROADCAST groups in ONOS are
     * equivalent to P4Runtime Packet Replication Engine (PRE) Multicast
     * groups.
     *
     * @param deviceId the device where to install the group
     */
    private void insertMulticastGroup(DeviceId deviceId) {
        // Create a set with all ports currently known for this device.
        // We want to replicate packets on all these ports.
        Set<PortNumber> ports = deviceService.getPorts(deviceId)
                .stream()
                .map(Port::number)
                .collect(Collectors.toSet());

        final GroupDescription multicastGroup = Utils.forgeMulticastGroup(
                appId, deviceId, DEFAULT_BROADCAST_GROUP_ID, ports);

        groupService.addGroup(multicastGroup);
    }

    /**
     * Inserts a P4Runtime clone sessions to replicate packets to the CPU, i.e.
     * to generate packet-in to ONOS (controller).
     * <p>
     * Since ONOS does not provide yet Suways to abstract clone sessions in its
     * northbound and core APIs, we use directly the same P4Runtime client
     * object used by ONOS to communicate with the device.
     *
     * @param deviceId device where to install the clone session
     */
    private void insertCpuCloneSession(DeviceId deviceId) {
        final P4RuntimeClient client = p4RuntimeController.get(deviceId);
        final PiPipeconf pipeconf = pipeconfService.getPipeconf(deviceId).orElse(null);
        if (pipeconf == null) {
            log.error("Unable to insert CPU clone session in {}, missing pipeconf", deviceId);
            return;
        }
        final PortNumber cpuPort = PortNumber.portNumber(CPU_PORT_ID);
        final PiCloneSessionEntry cpuCloneSession = PiCloneSessionEntry.builder()
                .withSessionId(CPU_CLONE_SESSION_ID)
                .addReplica(new PiPreReplica(cpuPort, 0))
                .build();
        client.write(P4RUNTIME_DEVICE_ID, pipeconf)
                .insert(cpuCloneSession)
                .submit()
                .thenAccept(response -> {
                    if (!response.isSuccess()) {
                        log.error("Unable to insert CPU clone session in {}", deviceId);
                    }
                });
    }

    /**
     * Deletes the P4Runtime CPU clone session previously installed.
     *
     * @param deviceId device where to delete the clone session
     */
    private void deleteCpuCloneSession(DeviceId deviceId) {
        final P4RuntimeClient client = p4RuntimeController.get(deviceId);
        final PiPipeconf pipeconf = pipeconfService.getPipeconf(deviceId).orElse(null);
        if (pipeconf == null) {
            log.error("Unable to delete CPU clone session from {}, missing pipeconf", deviceId);
            return;
        }
        final PiCloneSessionEntryHandle sessionHandle = PiCloneSessionEntryHandle
                .of(deviceId, CPU_CLONE_SESSION_ID);
        client.write(P4RUNTIME_DEVICE_ID, pipeconf)
                .delete(sessionHandle)
                .submit()
                .thenAccept(response -> {
                    if (!response.isSuccess()) {
                        log.error("Unable to delete CPU clone session from {}", deviceId);
                    }
                });
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
