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

import org.onlab.packet.Ip6Address;
import org.onlab.util.SharedScheduledExecutors;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.osgi.service.component.annotations.*;
import org.p4.p4d2.tutorial.common.Srv6DeviceConfig;
import org.p4.p4d2.tutorial.common.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static com.google.common.collect.Streams.stream;
import static org.p4.p4d2.tutorial.AppConstants.INITIAL_SETUP_DELAY;

/**
 * Application which handles IPv6 routing.
 */
@Component(immediate = true, service = Srv6App.class)
public class Srv6App {

    private static final Logger log = LoggerFactory.getLogger(Srv6App.class);

    private static final String APP_NAME = AppConstants.APP_PREFIX + ".srv6";

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    private final DeviceListener deviceListener = new Srv6App.InternalDeviceListener();

    private ApplicationId appId;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);

        // Wait to remove flow and groups from previous executions.
        Utils.waitPreviousCleanup(appId, deviceService, flowRuleService, null);

        // Register listeners to be informed about device and host events.
        deviceService.addListener(deviceListener);

        // Schedule set up for all devices.
        SharedScheduledExecutors.newTimeout(
                this::setUpAllDevices, INITIAL_SETUP_DELAY, TimeUnit.SECONDS);

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
     * Sets up SRv6 My SID table on all devices known by ONOS and for which this ONOS
     * node instance is currently master.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes
        stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .forEach(this::setUpMySidTable);
    }

    /**
     * Cleans up SRv6 My SID table and any custom insert policies.
     */
    private void cleanUpAllDevices() {
        Collection<DeviceId> deviceIds = stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .collect(Collectors.toSet());

        for (DeviceId deviceId : deviceIds) {
            FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
            stream(flowRuleService.getFlowEntries(deviceId))
                    .filter(fe -> fe.appId() == appId.id())
                    .forEach(ops::remove);
            flowRuleService.apply(ops.build());
        }
    }

    /**
     * Populate the My SID table from the network configuration for the specified device.
     *
     * @param deviceId the device Id
     */
    private void setUpMySidTable(DeviceId deviceId) {
        getDeviceConfig(deviceId).ifPresent(config -> {
            Ip6Address mySid = config.mySid();
            PiCriterion match = PiCriterion.builder()
                    .matchTernary(PiMatchFieldId.of("hdr.ipv6.dst_addr"),
                            mySid.toOctets(), Ip6Address.makeMaskPrefix(128).toOctets())
                    .build();
            PiTableAction action = PiAction.builder()
                    .withId(PiActionId.of("FabricIngress.srv6_end"))
                    .build();

            FlowRule myStationRule = Utils.forgeFlowRule(
                    deviceId, appId,
                    "FabricIngress.srv6_my_sid",
                    match, action);

            flowRuleService.applyFlowRules(myStationRule);
        });
    }

    /**
     * Insert a SRv6 transit insert policy that will inject an SRv6 header for packets destined to destIp.
     *
     * @param deviceId     device ID
     * @param destIp       target IP address for the SRv6 policy
     * @param prefixLength prefix length for the target IP
     * @param segmentList  list of SRv6 SIDs that make up the path
     */
    public void insertSrv6InsertRule(DeviceId deviceId, Ip6Address destIp, int prefixLength,
                                     List<Ip6Address> segmentList) {

        PiCriterion match = PiCriterion.builder()
                .matchLpm(PiMatchFieldId.of("hdr.ipv6.dst_addr"), destIp.toOctets(), prefixLength)
                .build();


        if (segmentList.size() < 2 || segmentList.size() > 3) {
            throw new RuntimeException("List of " + segmentList.size() + " segments is not supported");
        }

        AtomicInteger segmentIndex = new AtomicInteger();
        List<PiActionParam> actionParams = segmentList.stream()
                .map(segment -> new PiActionParam(
                        PiActionParamId.of("s" + segmentIndex.incrementAndGet()), segment.toOctets()))
                .collect(Collectors.toList());

        PiAction action = PiAction.builder()
                .withId(PiActionId.of("FabricIngress.srv6_t_insert_" + segmentIndex.get()))
                .withParameters(actionParams)
                .build();

        final FlowRule rule = Utils.forgeFlowRule(
                deviceId, appId,
                "FabricIngress.srv6_transit",
                match, action);

        flowRuleService.applyFlowRules(rule);
    }

    /**
     * Remove all SRv6 transit insert polices for the specified device.
     *
     * @param deviceId device ID
     */
    public void clearSrv6InsertRules(DeviceId deviceId) {
        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
        stream(flowRuleService.getFlowEntries(deviceId))
                .filter(fe -> fe.appId() == appId.id())
                .filter(fe -> fe.table().equals(PiTableId.of("FabricIngress.srv6_transit")))
                .forEach(ops::remove);
        flowRuleService.apply(ops.build());
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

    public class InternalDeviceListener implements DeviceListener {
        @Override
        public boolean isRelevant(DeviceEvent event) {
            return mastershipService.isLocalMaster(event.subject().id()) &&
                    !event.type().equals(DeviceEvent.Type.DEVICE_REMOVED);
        }

        @Override
        public void event(DeviceEvent event) {
            setUpMySidTable(event.subject().id());
        }
    }
}
