
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
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.service.PiPipeconfService;
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

@Component(immediate = true)
public class L2BridgingApp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String APP_NAME = APP_PREFIX + ".l2bridging";

    private static final int INITIAL_SETUP_DELAY = 5; // Seconds.
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

    private void cleanUpAllDevices() {
        deviceService.getDevices().forEach(device -> {
            if (mastershipService.isLocalMaster(device.id())) {
                cleanUpDevice(device.id());
            }
        });
    }

    private void setUpDevice(DeviceId deviceId) {
        log.info("Setting up L2 bridging on {}...", deviceId);

        createOrUpdateBroadcastGroup(deviceId);
        // create l2_broadcast_rules

        // Action: set multicast group id
        final PiAction l2MulticastAction = PiAction.builder()
                .withId(PiActionId.of("FabricIngress.l2_multicast_fwd"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("gid"),
                        DEFAULT_BROADCAST_GROUP_ID))
                .build();

        // Match exactly FF:FF:FF:FF:FF
        final PiCriterion macBroadcastCriterion = PiCriterion.builder()
                .matchTernary(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        MacAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes(),
                        MacAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes())
                .build();

        // Match ternary 33:33:**:**:**:**
        final PiCriterion ipv6MulticastCriterion = PiCriterion.builder()
                .matchTernary(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        MacAddress.valueOf("33:33:00:00:00:00").toBytes(),
                        MacAddress.valueOf("FF:FF:00:00:00:00").toBytes())
                .build();

        final PiTableId l2BroadcastTable = PiTableId.of("FabricIngress.l2_broadcast_table");

        final FlowRule rule1 = Utils.forgeFlowRule(
                deviceId, appId, l2BroadcastTable,
                macBroadcastCriterion, l2MulticastAction);
        final FlowRule rule2 = Utils.forgeFlowRule(
                deviceId, appId, l2BroadcastTable,
                ipv6MulticastCriterion, l2MulticastAction);

        flowRuleService.applyFlowRules(rule1, rule2);
    }

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
                .withId(PiActionId.of("FabricIngress.l2_unicast_fwd"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("port_num"),
                        port.toLong()))
                .build();

        final PiTableId l2BroadcastTable = PiTableId.of("FabricIngress.l2_table");

        final FlowRule rule = Utils.forgeFlowRule(
                deviceId, appId, l2BroadcastTable,
                hostMacCriterion, l2UnicastAction);

        flowRuleService.applyFlowRules(rule);
    }

    private void forgetHost(Host host, DeviceId deviceId) {
        log.info("Removing L2 bridging rule for host {} at {}...",
                 host.id(), deviceId);

        log.warn("forgetHost() not implemented yet");
    }

    private void createOrUpdateBroadcastGroup(DeviceId deviceId) {
        // Create a set with all ports currently known for this device.
        // We want to replicate packets on all these ports.
        Set<PortNumber> ports = deviceService.getPorts(deviceId)
                .stream()
                .map(Port::number)
                .collect(Collectors.toSet());

        // We add the CPU port to support cloning of ARP/NDP packets for host
        // discovery. This is a workaround to the lack of support in ONOS for
        // P4Runtime clone sessions, which would be the right way of supporting
        // packet cloning.
        ports.add(PortNumber.CONTROLLER);

        final GroupDescription multicastGroup = Utils.forgeMulticastGroup(
                appId, deviceId, DEFAULT_BROADCAST_GROUP_ID, ports);

        groupService.addGroup(multicastGroup);

        // FIXME: does the group service support updating an existing group?
    }

    private void cleanUpDevice(DeviceId deviceId) {
        log.info("Cleaning up L2 bridging on {}...", deviceId);

        // Remove all flows and groups installed by this app.
        flowRuleService.removeFlowRulesById(appId);
        groupService.getGroups(deviceId, appId).forEach(
                group -> groupService.removeGroup(deviceId, group.appCookie(), appId));
    }

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
                case HOST_MOVED:
                    //  If host moved we overwrite the previous table entry.
                    learnHost(host, deviceId, port);
                    break;
                case HOST_REMOVED:
                    forgetHost(host, deviceId);
                    break;
                default:
                    // Ignore other types of events.
            }
        }
    }
}
