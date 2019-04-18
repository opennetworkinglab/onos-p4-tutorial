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

import com.google.common.base.Preconditions;
import com.google.common.collect.Streams;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.util.SharedScheduledExecutors;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.Link;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.FlowRuleOperationsContext;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.DefaultGroupBucket;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.link.LinkListener;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiActionProfileId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroupId;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.store.service.StorageService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.p4.p4d2.tutorial.common.Srv6DeviceConfig;
import org.p4.p4d2.tutorial.common.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.p4.p4d2.tutorial.AppConstants.INITIAL_SETUP_DELAY;

/**
 * Application which handles IPv6 routing.
 */
@Component(immediate = true)
public class Ipv6Routing {
    private static final Logger log = LoggerFactory.getLogger(Ipv6Routing.class);
    private static final String APP_NAME = AppConstants.APP_PREFIX + ".ipv6routing";
    private static final long GROUP_INSTALLATION_DELAY = 500;
    private static final int DEFAULT_ECMP_GROUP_ID = 0xec3b0000;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkService linkService;

    private ApplicationId appId;
    private HostListener hostListener = new InternalHostListener();
    private DeviceListener deviceListener = new InternalDeviceListener();
    private LinkListener linkListener = new InternalLinkListener();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);
        hostService.addListener(hostListener);
        deviceService.addListener(deviceListener);
        linkService.addListener(linkListener);
        SharedScheduledExecutors.newTimeout(
                this::setUpAllDevices, INITIAL_SETUP_DELAY, TimeUnit.SECONDS);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        deviceService.removeListener(deviceListener);
        linkService.removeListener(linkListener);
        clearAllDevices();
        log.info("Stopped");
    }

    /**
     * Initialize all devices.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes
        Streams.stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .forEach(deviceId -> {
                    setUpMyStationTable(deviceId);
                    setUpRoute(deviceId);
                    setUpNextHopRules(deviceId);
                    setUpHostRulesOnDevice(deviceId);
                });
    }

    /**
     * Remove all flow rules and groups installed by this app.
     */
    private void clearAllDevices() {
        Collection<DeviceId> deviceIds = Streams
                .stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .collect(Collectors.toSet());

        for (DeviceId deviceId : deviceIds) {
            FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
            FlowRuleOperationsContext callback = new FlowRuleOperationsContext() {
                @Override
                public void onSuccess(FlowRuleOperations ops) {
                    Streams.stream(groupService.getGroups(deviceId, appId))
                            .filter(group -> group.appId().equals(appId))
                            .forEach(group -> groupService.removeGroup(deviceId, group.appCookie(), appId));
                }
            };
            Streams.stream(flowRuleService.getFlowEntries(deviceId))
                    .filter(fe -> fe.appId() == appId.id())
                    .forEach(ops::remove);
            flowRuleService.apply(ops.build(callback));
        }
    }

    /**
     * Set up my station table for a device.
     *
     * @param deviceId the device Id
     */
    private void setUpMyStationTable(DeviceId deviceId) {
        MacAddress myStationMac = getDeviceMac(deviceId).orElse(null);
        if (myStationMac == null) {
            log.debug("Can not find my station mac for device {}", deviceId);
            return;
        }
        PiCriterion match = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("hdr.ethernet.dst_addr"), myStationMac.toBytes())
                .build();
        PiTableAction action = PiAction.builder().withId(PiActionId.of("NoAction")).build();

        FlowRule myStationRule = Utils.forgeFlowRule(deviceId,
                                                     appId, "FabricIngress.l2_my_station",
                                                     match, action);

        flowRuleService.applyFlowRules(myStationRule);
    }

    /**
     * Set up nexthop rules of a device.
     *
     * @param deviceId the device id
     */
    private void setUpNextHopRules(DeviceId deviceId) {
        deviceService.getAvailableDevices().forEach(dstDevice -> {
            DeviceId dstDeviceId = dstDevice.id();
            Set<Link> egressLinks = linkService.getDeviceEgressLinks(deviceId);
            Link linkConnectToDst = egressLinks.stream()
                    .filter(link -> link.dst().deviceId().equals(dstDeviceId))
                    .findFirst()
                    .orElse(null);

            if (linkConnectToDst == null) {
                // destination invalid, the link may not comes up yet
                log.debug("Can't find link between {} and {}", deviceId, dstDeviceId);
                return;
            }

            MacAddress dstDeviceMac = getDeviceMac(dstDeviceId).orElse(null);
            if (dstDeviceMac == null) {
                log.debug("Can not find device mac for device {}", dstDeviceId);
                return;
            }
            // Gets output port from first link of path
            PortNumber outputPort = linkConnectToDst.src().port();
            setUpNexthopRule(deviceId, dstDeviceMac, outputPort);
        });
    }

    /**
     * Set up nexthop rule for a device with given mac and port.
     *
     * @param deviceId the device
     * @param dstMac the destination mac
     * @param outputPort the output port
     */
    private void setUpNexthopRule(DeviceId deviceId, MacAddress dstMac,
                                  PortNumber outputPort) {

        // Matches mac address of the next hop.
        PiCriterion match = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("hdr.ethernet.dst_addr"), dstMac.toBytes())
                .build();

        // Sets output port action
        PiActionParam param = new PiActionParam(PiActionParamId.of("port_num"),
                outputPort.toLong());
        PiAction action = PiAction.builder()
                .withId(PiActionId.of("FabricIngress.set_output_port"))
                .withParameter(param)
                .build();

        final FlowRule rule = Utils.forgeFlowRule(
                deviceId,
                appId,
                "FabricIngress.l2_exact_table",
                match, action);

        flowRuleService.applyFlowRules(rule);
    }

    private void setUpHostRulesOnDevice(DeviceId deviceId) {
        hostService.getConnectedHosts(deviceId)
                .forEach(this::setUpHostRules);
    }

    /**
     * Set up rules for host which connect to the switch.
     *
     * @param host the host
     */
    private void setUpHostRules(Host host) {
        MacAddress hostMac = host.mac();
        DeviceId hostDevice = host.location().deviceId();
        log.info("Setting up host route: {}", hostMac);

        // Get all IPv6 address from the host
        Collection<Ip6Address> hostIpv6s = host.ipAddresses()
                .stream()
                .filter(IpAddress::isIp6)
                .map(IpAddress::getIp6Address)
                .collect(Collectors.toSet());

        int groupId = createGroupIdFromNextHopMac(hostMac);
        GroupDescription group = createNextHopGroups(groupId, hostMac, hostDevice);

        // Creates rules for the host
        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
        hostIpv6s.stream()
                .map(IpAddress::toIpPrefix)
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .map(ipPrefix -> createIpv6RoutingRule(groupId, ipPrefix, hostDevice))
                .forEach(ops::add);

        installGroupAndFlows(group, ops.build());
    }

    /**
     * Set up routes on a device.
     *
     * @param deviceId the device id.
     */
    private void setUpRoute(DeviceId deviceId) {
        Optional<Boolean> isSpineOrUnknown = isSpine(deviceId);
        if (!isSpineOrUnknown.isPresent()) {
            log.debug("No device config found, cannot set up the route on the device {}", deviceId);
            return;
        }
        if (isSpineOrUnknown.get()) {
            setUpSpineRoutes(deviceId);
        } else {
            setUpLeafRoutes(deviceId);
        }
    }

    /**
     * Install route rules for spine.
     *
     * @param spineDeviceId the spine device id
     */
    private void setUpSpineRoutes(DeviceId spineDeviceId) {
        log.info("Setting up spine routes: {}", spineDeviceId);

        deviceService.getAvailableDevices().forEach(device -> {
            if (isSpine(device.id()).orElse(true)) {
                // skip if it is a spine or unknown
                return;
            }
            DeviceId leafDeviceId = device.id();
            Set<Ip6Prefix> subnetSet = getDeviceSubnet(leafDeviceId);
            MacAddress leafMac = getDeviceMac(leafDeviceId).orElse(null);

            if (leafMac == null) {
                log.debug("Cannot fine mac address for leaf {}, skip", leafDeviceId);
                return;
            }

            int groupId = createGroupIdFromNextHopMac(leafMac);
            GroupDescription group = createNextHopGroups(groupId, leafMac, spineDeviceId);

            FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
            subnetSet.forEach(subnet -> {
                ops.add(createIpv6RoutingRule(groupId, subnet, spineDeviceId));
            });

            installGroupAndFlows(group, ops.build());
        });
    }

    /**
     * Install route rules for a leaf device.
     *
     * @param leafDeviceId the leaf device id
     */
    private void setUpLeafRoutes(DeviceId leafDeviceId) {
        log.info("Setting up leaf routes: {}", leafDeviceId);
        // Collect mac address from spines
        Set<MacAddress> spineMacs =
                Streams.stream(deviceService.getAvailableDevices())
                        .map(Device::id)
                        .filter(deviceId -> isSpine(deviceId).orElse(false))
                        .map(deviceId -> getDeviceMac(deviceId).orElse(null))
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet());

        if (spineMacs.isEmpty()) {
            // No mac address for spine found, the spine may not be configured yet.
            return;
        }

        GroupDescription group =
                createNextHopGroups(DEFAULT_ECMP_GROUP_ID, spineMacs, leafDeviceId);

        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
        deviceService.getAvailableDevices().forEach(device -> {
            if (device.id().equals(leafDeviceId)) {
                // don't need to install route for leaf itself
                return;
            }
            Set<Ip6Prefix> subnets = getDeviceSubnet(device.id());
            subnets.forEach(subnet -> {
                ops.add(createIpv6RoutingRule(DEFAULT_ECMP_GROUP_ID, subnet, leafDeviceId));
            });
        });

        installGroupAndFlows(group, ops.build());
    }

    /**
     * Creates next hop group with a single next hop.
     *
     * @param nextHop the mac address of next hop
     * @param deviceId the device to install the group
     * @return an ECMP group with single set_l2_next_hop group member
     */
    private GroupDescription createNextHopGroups(int groupId, MacAddress nextHop, DeviceId deviceId) {
        return createNextHopGroups(groupId, Collections.singleton(nextHop), deviceId);
    }

    /**
     * Creates next hop group with multiple next hops.
     *
     * @param nextHops the collection of mac address of next hops
     * @param deviceId the device to install the group
     * @return an ECMP group with one or more set_l2_next_hop group member
     */
    private GroupDescription createNextHopGroups(int groupId, Collection<MacAddress> nextHops, DeviceId deviceId) {
        Preconditions.checkState(!nextHops.isEmpty(), "Nex thop list can not be empty");

        // Create list of buckets, each bucket sets different next hop address.
        final List<GroupBucket> bucketList = nextHops.stream()
                .map(mac -> new PiActionParam(PiActionParamId.of("dmac"), mac.toBytes()))
                .map(param -> PiAction.builder()
                        .withId(PiActionId.of("FabricIngress.set_l2_next_hop"))
                        .withParameter(param).build())
                .map(action -> DefaultTrafficTreatment.builder()
                        .piTableAction(action).build())
                .map(DefaultGroupBucket::createSelectGroupBucket)
                .collect(Collectors.toList());
        GroupBuckets buckets = new GroupBuckets(bucketList);

        return Utils.forgeSelectGroup(
                deviceId,
                PiTableId.of("FabricIngress.l3_table"),
                PiActionProfileId.of("FabricIngress.ecmp_selector"),
                groupId,
                buckets,
                appId);
    }

    /**
     * Creates a routing rules for an IPv6 prefix and a next hop group.
     *
     * @param nextHopGroupId the group id point to the next hop group
     * @param ip6Prefix prefix of a route
     * @param deviceId the device to install the rule
     * @return a routing rule of the l3_table
     */
    private FlowRule createIpv6RoutingRule(int nextHopGroupId,
                                           Ip6Prefix ip6Prefix,
                                           DeviceId deviceId) {

        // Matches an IPv6 with prefix length.
        PiCriterion match = PiCriterion.builder()
                .matchLpm(PiMatchFieldId.of("hdr.ipv6.dst_addr"),
                        ip6Prefix.address().toOctets(),
                        ip6Prefix.prefixLength())
                .build();

        // Sets next hop group.
        PiTableAction action = PiActionProfileGroupId.of(nextHopGroupId);

        return Utils.forgeFlowRule(deviceId,
                                   appId, "FabricIngress.l3_table", match, action);
    }

    /**
     * Indicate that the device is a spine or not.
     *
     * @param deviceId the device id
     * @return true if the device is a spine, false otherwise
     */
    private Optional<Boolean> isSpine(DeviceId deviceId) {
        return getDeviceConfig(deviceId).map(Srv6DeviceConfig::isSpine);
    }

    /**
     * Gets device mac address (my station mac).
     *
     * @param deviceId the device id
     * @return device mac address
     */
    private Optional<MacAddress> getDeviceMac(DeviceId deviceId) {
        return getDeviceConfig(deviceId).map(Srv6DeviceConfig::myStationMac);
    }

    /**
     * Gets device config of a device.
     *
     * @param deviceId the device id
     * @return device config
     */
    private Optional<Srv6DeviceConfig> getDeviceConfig(DeviceId deviceId) {
        Srv6DeviceConfig config = networkConfigService.getConfig(deviceId, Srv6DeviceConfig.class);
        return Optional.ofNullable(config);
    }

    /**
     * Gets a set of subnet from interfaces which fro specific device.
     *
     * @param deviceId the device id
     * @return a set of subnet
     */
    private Set<Ip6Prefix> getDeviceSubnet(DeviceId deviceId) {
        return interfaceService.getInterfaces().stream()
                .filter(iface -> iface.connectPoint().deviceId().equals(deviceId))
                .map(Interface::ipAddressesList)
                .flatMap(Collection::stream)
                .map(InterfaceIpAddress::subnetAddress)
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .collect(Collectors.toSet());
    }

    /**
     * Creates a single next hop group id from a mac address.
     *
     * @param mac the mac address
     * @return a group id for the next hop
     */
    private int createGroupIdFromNextHopMac(MacAddress mac) {
        return mac.hashCode() & 0x7fffffff;
    }

    /**
     * Installs groups and apply flow operations.
     *
     * @param group the group
     * @param ops the flow operations
     */
    private void installGroupAndFlows(GroupDescription group, FlowRuleOperations ops) {
        try {
            groupService.addGroup(group);
            Thread.sleep(GROUP_INSTALLATION_DELAY);
            flowRuleService.apply(ops);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Host listener which listens HOST_ADD event.
     */
    class InternalHostListener implements HostListener {
        @Override
        public void event(HostEvent event) {
            switch (event.type()) {
                case HOST_ADDED:
                case HOST_UPDATED:
                    setUpHostRules(event.subject());
                    break;
                default:
                    log.warn("Unsupported event type {}", event.type());
                    break;
            }
        }

        @Override
        public boolean isRelevant(HostEvent event) {
            return mastershipService.isLocalMaster(event.subject().location().deviceId());
        }
    }

    /**
     * Device listener which listens DEVICE_ADDED and DEVICE_AVAILABILITY_CHANGED
     * event.
     */
    class InternalDeviceListener implements DeviceListener {

        @Override
        public void event(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_ADDED:
                case DEVICE_AVAILABILITY_CHANGED:
                    setUpAllDevices();
                    break;
                default:
                    log.debug("Unsupported event type {}", event.type());
                    break;
            }
        }

        @Override
        public boolean isRelevant(DeviceEvent event) {
            return mastershipService.isLocalMaster(event.subject().id());
        }
    }

    /**
     * Link listener which listens LINK_ADDED event.
     */
    class InternalLinkListener implements LinkListener {

        @Override
        public void event(LinkEvent event) {
            switch (event.type()) {
                case LINK_ADDED:
                    setUpAllDevices();
                    break;
                default:
                    log.debug("Unsupported event type {}", event.type());
                    break;
            }
        }
    }
}
