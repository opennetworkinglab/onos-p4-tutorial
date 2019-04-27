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

import com.google.common.collect.Lists;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.Link;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
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
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroupId;
import org.onosproject.net.pi.runtime.PiTableAction;
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
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.google.common.collect.Streams.stream;
import static org.p4.p4d2.tutorial.AppConstants.INITIAL_SETUP_DELAY;

/**
 * Application which handles IPv6 routing.
 */
@Component(
        immediate = true,
        enabled = true
)
public class Ipv6RoutingComponent {

    private static final Logger log = LoggerFactory.getLogger(Ipv6RoutingComponent.class);

    private static final long GROUP_INSTALLATION_DELAY = 200;

    private static final int DEFAULT_ECMP_GROUP_ID = 0xec3b0000;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    private final HostListener hostListener = new InternalHostListener();
    private final LinkListener linkListener = new InternalLinkListener();

    private ApplicationId appId;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        hostService.addListener(hostListener);
        linkService.addListener(linkListener);

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        linkService.removeListener(linkListener);

        log.info("Stopped");
    }

    /**
     * Sets up IPv6 routing on all devices known by ONOS and for which this ONOS
     * node instance is currently master.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes
        stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .forEach(deviceId -> {
                    log.info("*** IPV6 ROUTING - Starting initial set up for {}...", deviceId);
                    setUpMyStationTable(deviceId);
                    setUpRoute(deviceId);
                    setUpNextHopRules(deviceId);
                    setUpHostRulesOnDevice(deviceId);
                });
    }

    /**
     * Sets up my station table for the given device with the myStationMac
     * address found in the config.
     *
     * @param deviceId the device Id
     */
    private void setUpMyStationTable(DeviceId deviceId) {
        MacAddress myStationMac = getMyStationMac(deviceId);

        // HINT: this method create a flow rule for *l2_my_station* table
        //       which matches the *ethernet destination*
        //       and there is only one action called *NoAction*
        String tableId = "FabricIngress.l2_my_station";

        // TODO: create a match which matches my station mac address.
        // HINT: uses *.matchExact* to match exact byte value of dst mac.
        // ---- START SOLUTION ----
        PiCriterion piMatch = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        myStationMac.toBytes())
                .build();

        // Creates an action which do *NoAction* when hit.
        PiTableAction piTableAction = PiAction.builder()
                .withId(PiActionId.of("NoAction"))
                .build();
        // ---- END SOLUTION ----

        FlowRule myStationRule = Utils.forgeFlowRule(
                deviceId, appId,
                tableId,
                piMatch, piTableAction);

        flowRuleService.applyFlowRules(myStationRule);
    }

    /**
     * Creates a next hope flow rule in the L2 table, matching on the given
     * destination MAC and with the given output port.
     *
     * @param deviceId the device
     * @param nexthopMac   the next hop (destination) mac
     * @param outPort  the output port
     */
    private FlowRule createNextHopRule(DeviceId deviceId, MacAddress nexthopMac,
                                       PortNumber outPort) {
        // HINT: this method create a flow for *l2_exact_table* table
        //       which matches the *ethernet destination* and sets the output
        //       port by invoking *set_output_port* action.
        String tableId = "FabricIngress.l2_exact_table";

        // FIXME TODO: create a match which matches destination mac to next hop
        PiCriterion match = PiCriterion.builder()
                // TODO: add code here
                .matchExact(PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                            nexthopMac.toBytes())
                .build();

        // TODO: create an action which sets the output port
        // HINT: use *withId* method to set action id and use *withParameter*
        //       to set action parameter
        PiAction action = PiAction.builder()
                // TODO: add code here
                .withId(PiActionId.of("FabricIngress.set_output_port"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("port_num"), outPort.toLong()))
                .build();

        return Utils.forgeFlowRule(
                deviceId, appId,
                tableId,
                match, action);
    }

    /**
     * Creates an ONOS SELECT group to provide ECMP forwarding for the given
     * collection of next hop MAC addresses. ONOS SELECT groups are equivalent
     * to P4Runtime action selector groups.
     *
     * @param nextHopMacs the collection of mac addresses of next hops
     * @param deviceId    the device where the group will be installed
     * @return a SELECT group
     */
    private GroupDescription createNextHopGroup(
            int groupId, Collection<MacAddress> nextHopMacs, DeviceId deviceId) {

        // TODO: Fill Ids.
        // HINT: this method creates an group for *l3_table* and uses
        //       *ecmp_selector* action profile group to do ECMP.
        String tableId = "FabricIngress.l3_table";
        String actionProfileId = "FabricIngress.ecmp_selector";

        final List<PiAction> actions = Lists.newArrayList();
        for (MacAddress nextHopMac : nextHopMacs) {
            // TODO: Create a list of actions for each next hop.
            // HINT: add action and action parameter
            // ---- START SOLUTION ----
            PiAction action = PiAction.builder()
                    // TODO: add code here
                    .withId(PiActionId.of("FabricIngress.set_l2_next_hop"))
                    .withParameter(new PiActionParam(
                            PiActionParamId.of("dmac"),
                            nextHopMac.toBytes()))
                    .build();
            // ---- END SOLUTION ----
            actions.add(action);
        }

        return Utils.forgeSelectGroup(
                deviceId, tableId, actionProfileId, groupId, actions, appId);
    }

    /**
     * Creates a routing flow rule that matches on the given IPv6 prefix and
     * executes the given group ID.
     *
     * @param deviceId  the device where flow rule will be installed
     * @param ip6Prefix the IPv6 prefix
     * @param groupId   the group ID
     * @return a flow rule
     */
    private FlowRule createRoutingRule(
            DeviceId deviceId, Ip6Prefix ip6Prefix, int groupId) {

        // TODO: Fill Ids.
        // HINT: the routing rule matches *destination IP* and forward the
        //       packet to the next hop group
        String tableId = "FabricIngress.l3_table";

        // TODO: Cerate a match for IPv6 address with LPM.
        // HINT: use *matchLpm* to match LPM
        // ---- START SOLUTION ----
        PiCriterion match = PiCriterion.builder()
                // TODO: add code here
                .matchLpm(PiMatchFieldId.of("hdr.ipv6.dst_addr"),
                        ip6Prefix.address().toOctets(),
                        ip6Prefix.prefixLength())
                .build();
        // ---- END SOLUTION ----

        // FIXME make TODO
        // Action: set action profile group ID
        PiTableAction action = PiActionProfileGroupId.of(groupId);

        return Utils.forgeFlowRule(deviceId, appId, tableId, match, action);
    }

    // ---------- end methods to work on ---------------- FIXME

    /**
     * Set up nexthop rules of a device.
     *
     * @param deviceId the device ID
     */
    private void setUpNextHopRules(DeviceId deviceId) {
        Set<Link> egressLinks = linkService.getDeviceEgressLinks(deviceId);
        for (Link link : egressLinks) {
            DeviceId nextHopDevice = link.dst().deviceId();
            // Get port of this device connecting to next hop.
            PortNumber outPort = link.src().port();
            MacAddress nextHopMac = getMyStationMac(nextHopDevice);
            final FlowRule nextHopRule = createNextHopRule(deviceId, nextHopMac, outPort);
            flowRuleService.applyFlowRules(nextHopRule);
        }
    }

    /**
     * Sets up the given device with the necessary rules to route packets to the
     * given host.
     *
     * @param deviceId deviceId the device ID
     * @param host     the host
     */
    private void setUpHostRules(DeviceId deviceId, Host host) {
        MacAddress hostMac = host.mac();

        // Get all IPv6 addresses associated to this host. In this tutorial we
        // use hosts with onle 1 IPv6 address.
        Collection<Ip6Address> hostIpv6Addresses = host.ipAddresses().stream()
                .filter(IpAddress::isIp6)
                .map(IpAddress::getIp6Address)
                .collect(Collectors.toSet());

        if (hostIpv6Addresses.isEmpty()) {
            // Ignore.
            log.debug("No IPv6 addresses for host {}, ignore", hostMac);
            return;
        } else {
            log.info("Setting up routes on {} for host {} [{}]",
                    deviceId, host.id(), hostIpv6Addresses);
        }

        // Create a group with only one member.
        int groupId = macToGroupId(hostMac);
        GroupDescription group = createNextHopGroup(
                groupId, Collections.singleton(hostMac), deviceId);

        // Map each address to corresponding /128 prefix and obtain a flow rule
        // that points to the group ID.
        List<FlowRule> flowRules = hostIpv6Addresses.stream()
                .map(IpAddress::toIpPrefix)
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .map(prefix -> createRoutingRule(deviceId, prefix, groupId))
                .collect(Collectors.toList());

        // Helper function to install flows after group.
        insertInOrder(group, flowRules);
    }

    /**
     * Set up routes on a device.
     *
     * @param deviceId the device ID.
     */
    private void setUpRoute(DeviceId deviceId) {
        if (isSpine(deviceId)) {
            setUpSpineRoutes(deviceId);
        } else {
            setUpLeafRoutes(deviceId);
        }
    }

    /**
     * Install routing rules on the given spine switch, for each leaf interface
     * subnet.
     *
     * @param spineId the spine device id
     */
    private void setUpSpineRoutes(DeviceId spineId) {
        log.info("Setting up spine routes: {}", spineId);

        for (Device device : deviceService.getDevices()) {
            if (isSpine(device.id())) {
                // We only need routes to leaf switches. Next device.
                continue;
            }
            DeviceId leafId = device.id();
            MacAddress leafMac = getMyStationMac(leafId);
            final Set<Ip6Prefix> subnetsToRoute = getInterfaceIpv6Prefixes(leafId);

            // Add direct routing rule for spine to leaf
            Ip6Address leafSid = getDeviceSid(leafId);
            subnetsToRoute.add(Ip6Prefix.valueOf(leafSid, 128));

            if (subnetsToRoute.isEmpty()) {
                // No subnets on this leaf switch. Next device.
                continue;
            }

            // Create a group with only one member.
            int groupId = macToGroupId(leafMac);
            GroupDescription group = createNextHopGroup(
                    groupId, Collections.singleton(leafMac), spineId);

            List<FlowRule> flowRules = subnetsToRoute.stream()
                    .map(subnet -> createRoutingRule(spineId, subnet, groupId))
                    .collect(Collectors.toList());

            insertInOrder(group, flowRules);
        }
    }

    /**
     * Install route rules for a leaf device.
     *
     * @param leafId the leaf device id
     */
    private void setUpLeafRoutes(DeviceId leafId) {
        log.info("Setting up leaf routes: {}", leafId);

        // Get MAC address of all spines.
        Set<MacAddress> spineMacs = stream(deviceService.getDevices())
                .map(Device::id)
                .filter(this::isSpine)
                .map(this::getMyStationMac)
                .collect(Collectors.toSet());

        // Create an ECMP group to distribute traffic across all spines.
        final int groupId = DEFAULT_ECMP_GROUP_ID;
        final GroupDescription ecmpGroup = createNextHopGroup(
                groupId, spineMacs, leafId);

        // Get the set of subnets (interface IPv6 prefixes) associated to other
        // leafs but not this one.
        Set<Ip6Prefix> subnetsToRouteViaSpines = stream(deviceService.getDevices())
                .map(Device::id)
                .filter(this::isLeaf)
                .filter(deviceId -> !deviceId.equals(leafId))
                .map(this::getInterfaceIpv6Prefixes)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());

        // Generate a flow rule for each subnet to using the ECMP group as
        // action.
        List<FlowRule> flowRules = subnetsToRouteViaSpines.stream()
                .map(subnet -> createRoutingRule(leafId, subnet, groupId))
                .collect(Collectors.toList());

        insertInOrder(ecmpGroup, flowRules);

        // Add direct routing rule for leaf to spine
        stream(deviceService.getDevices())
                .map(Device::id)
                .filter(this::isSpine)
                .forEach(spineId -> {
                    MacAddress spineMac = getMyStationMac(spineId);
                    Ip6Address spineSid = getDeviceSid(spineId);
                    int spineGroupId = macToGroupId(spineMac);
                    GroupDescription group = createNextHopGroup(
                            spineGroupId, Collections.singleton(spineMac), leafId);
                    insertInOrder(group, Collections.singleton(
                            createRoutingRule(leafId, Ip6Prefix.valueOf(spineSid, 128),
                                    spineGroupId)));

                });
    }

    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    /**
     * Listener of host events which triggers configuration of routing rules on
     * the device where the host is attached.
     */
    class InternalHostListener implements HostListener {
        @Override
        public void event(HostEvent event) {
            Host host = event.subject();
            DeviceId deviceId = host.location().deviceId();
            mainComponent.getExecutorService().execute(() -> {
                log.info("{} event! host={}, deviceId={}, port={}",
                        event.type(), host.id(), deviceId, host.location().port());
                setUpHostRules(deviceId, host);
            });
        }

        @Override
        public boolean isRelevant(HostEvent event) {
            switch (event.type()) {
                case HOST_ADDED:
                    break;
                case HOST_REMOVED:
                case HOST_UPDATED:
                case HOST_MOVED:
                default:
                    // Ignore other events.
                    // Food for thoughts:
                    // how to support host moved/removed events?
                    return false;
            }
            // Process host event only if this controller instance is the master
            // for the device where this host is attached.
            final Host host = event.subject();
            final DeviceId deviceId = host.location().deviceId();
            return mastershipService.isLocalMaster(deviceId);
        }
    }

    /**
     * Listener of link events.
     */
    class InternalLinkListener implements LinkListener {

        @Override
        public void event(LinkEvent event) {
            DeviceId srcDev = event.subject().src().deviceId();
            DeviceId dstDev = event.subject().dst().deviceId();

            if (mastershipService.isLocalMaster(srcDev)) {
                mainComponent.getExecutorService().execute(() -> {
                    log.info("{} event! Configuring {}... linkSrc={}, linkDst={}",
                            event.type(), srcDev, srcDev, dstDev);
                    setUpRoute(srcDev);
                    setUpNextHopRules(srcDev);
                });
            }
            if (mastershipService.isLocalMaster(dstDev)) {
                mainComponent.getExecutorService().execute(() -> {
                    log.info("{} event! Configuring {}... linkSrc={}, linkDst={}",
                            event.type(), dstDev, srcDev, dstDev);
                    setUpRoute(dstDev);
                    setUpNextHopRules(dstDev);
                });
            }
        }

        @Override
        public boolean isRelevant(LinkEvent event) {
            switch (event.type()) {
                case LINK_ADDED:
                    break;
                case LINK_UPDATED:
                case LINK_REMOVED:
                default:
                    return false;
            }
            DeviceId srcDev = event.subject().src().deviceId();
            DeviceId dstDev = event.subject().dst().deviceId();
            return mastershipService.isLocalMaster(srcDev) ||
                    mastershipService.isLocalMaster(dstDev);
        }
    }

    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------

    private void setUpHostRulesOnDevice(DeviceId deviceId) {
        hostService.getConnectedHosts(deviceId)
                .forEach(host -> setUpHostRules(deviceId, host));
    }

    /**
     * Returns true if the given device has isSpine flag set to true in config,
     * false otherwise.
     *
     * @param deviceId the device ID
     * @return true if the device is a spine, false otherwise
     */
    private boolean isSpine(DeviceId deviceId) {
        return getDeviceConfig(deviceId).map(Srv6DeviceConfig::isSpine)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing isSpine config for " + deviceId));
    }

    /**
     * Returns true if the given device is not configured as spine.
     *
     * @param deviceId the device ID
     * @return true if the device is a leaf, false otherwise
     */
    private boolean isLeaf(DeviceId deviceId) {
        return !isSpine(deviceId);
    }

    /**
     * Returns the MAC address configured in the "myStationMac" property of the
     * given device config.
     *
     * @param deviceId the device ID
     * @return MyStation MAC address
     */
    private MacAddress getMyStationMac(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(Srv6DeviceConfig::myStationMac)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing myStationMac config for " + deviceId));
    }

    /**
     * Returns the Srv6 config for the given device.
     *
     * @param deviceId the device ID
     * @return Srv6  device config
     */
    private Optional<Srv6DeviceConfig> getDeviceConfig(DeviceId deviceId) {
        Srv6DeviceConfig config = networkConfigService.getConfig(deviceId, Srv6DeviceConfig.class);
        return Optional.ofNullable(config);
    }

    /**
     * Returns the set of IPv6 subnets (prefixes) configured for the given
     * device.
     *
     * @param deviceId the device ID
     * @return set of IPv6 prefixes
     */
    private Set<Ip6Prefix> getInterfaceIpv6Prefixes(DeviceId deviceId) {
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
     * Returns a 32 bit bit group ID from the given MAC address.
     *
     * @param mac the MAC address
     * @return an integer
     */
    private int macToGroupId(MacAddress mac) {
        return mac.hashCode() & 0x7fffffff;
    }

    /**
     * Inserts the given groups and flow rules in order, groups first, then flow
     * rules. In P4Runtime, when operating on an indirect table (i.e. with
     * action selectors), groups must be inserted before table entries.
     *
     * @param group     the group
     * @param flowRules the flow rules depending on the group
     */
    private void insertInOrder(GroupDescription group, Collection<FlowRule> flowRules) {
        try {
            groupService.addGroup(group);
            // Wait for groups to be inserted.
            Thread.sleep(GROUP_INSTALLATION_DELAY);
            flowRules.forEach(flowRuleService::applyFlowRules);
        } catch (InterruptedException e) {
            log.error("Interrupted!", e);
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Gets Srv6 SID for the given device.
     *
     * @param deviceId the device ID
     * @return SID for the device
     */
    private Ip6Address getDeviceSid(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(Srv6DeviceConfig::mySid)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing mySid config for " + deviceId));
    }
}
