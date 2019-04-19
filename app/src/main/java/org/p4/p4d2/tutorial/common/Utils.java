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

package org.p4.p4d2.tutorial.common;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.DefaultGroupBucket;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupKey;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.pi.model.PiActionProfileId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiGroupKey;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.onosproject.net.group.DefaultGroupBucket.createAllGroupBucket;
import static org.onosproject.net.group.DefaultGroupBucket.createCloneGroupBucket;
import static org.p4.p4d2.tutorial.AppConstants.CLEAN_UP_DELAY;
import static org.p4.p4d2.tutorial.AppConstants.DEFAULT_CLEAN_UP_RETRY_TIMES;
import static org.p4.p4d2.tutorial.AppConstants.DEFAULT_FLOW_RULE_PRIORITY;

public final class Utils {

    private static final Logger log = LoggerFactory.getLogger(Utils.class);

    public static GroupDescription forgeMulticastGroup(
            ApplicationId appId,
            DeviceId deviceId,
            int groupId,
            Collection<PortNumber> ports) {
        return forgeReplicationGroup(appId, deviceId, groupId, ports, false);
    }

    public static GroupDescription forgeCloneGroup(
            ApplicationId appId,
            DeviceId deviceId,
            int groupId,
            Collection<PortNumber> ports) {
        return forgeReplicationGroup(appId, deviceId, groupId, ports, true);
    }

    private static GroupDescription forgeReplicationGroup(
            ApplicationId appId,
            DeviceId deviceId,
            int groupId,
            Collection<PortNumber> ports,
            boolean isClone) {

        checkNotNull(deviceId);
        checkNotNull(appId);
        checkArgument(!ports.isEmpty());

        final GroupKey groupKey = new DefaultGroupKey(
                ByteBuffer.allocate(4).putInt(groupId).array());

        final List<GroupBucket> bucketList = ports.stream()
                .map(p -> DefaultTrafficTreatment.builder()
                        .setOutput(p).build())
                .map(t -> isClone ? createCloneGroupBucket(t)
                        : createAllGroupBucket(t))
                .collect(Collectors.toList());

        return new DefaultGroupDescription(
                deviceId,
                isClone ? GroupDescription.Type.CLONE : GroupDescription.Type.ALL,
                new GroupBuckets(bucketList),
                groupKey, groupId, appId);
    }

    public static FlowRule forgeFlowRule(DeviceId switchId, ApplicationId appId,
                                         String tableId, PiCriterion piCriterion,
                                         PiTableAction piAction) {
        return DefaultFlowRule.builder()
                .forDevice(switchId)
                .forTable(PiTableId.of(tableId))
                .fromApp(appId)
                .withPriority(DEFAULT_FLOW_RULE_PRIORITY)
                .makePermanent()
                .withSelector(DefaultTrafficSelector.builder()
                                      .matchPi(piCriterion).build())
                .withTreatment(DefaultTrafficTreatment.builder()
                                       .piTableAction(piAction).build())
                .build();
    }

    public static GroupDescription forgeSelectGroup(DeviceId deviceId,
                                                    String tableId,
                                                    String actionProfileId,
                                                    int groupId,
                                                    Collection<PiAction> actions,
                                                    ApplicationId appId) {

        final GroupKey groupKey = new PiGroupKey(
                PiTableId.of(tableId), PiActionProfileId.of(actionProfileId), groupId);
        final List<GroupBucket> buckets = actions.stream()
                .map(action -> DefaultTrafficTreatment.builder()
                        .piTableAction(action).build())
                .map(DefaultGroupBucket::createSelectGroupBucket)
                .collect(Collectors.toList());
        return new DefaultGroupDescription(
                deviceId,
                GroupDescription.Type.SELECT,
                new GroupBuckets(buckets),
                groupKey,
                groupId,
                appId);
    }

    public static void waitPreviousCleanup(ApplicationId appId,
                                           DeviceService deviceService,
                                           FlowRuleService flowRuleService,
                                           GroupService groupService) {
        int retry = DEFAULT_CLEAN_UP_RETRY_TIMES;
        while (retry != 0) {
            boolean existAnyFlows = flowRuleService.getFlowEntriesById(appId).iterator().hasNext();
            boolean existAnyGroups = false;

            if (groupService != null) {
                for (Device device : deviceService.getAvailableDevices()) {
                    existAnyGroups = existAnyGroups ||
                            groupService.getGroups(device.id(), appId).iterator().hasNext();
                }
            }

            if (!existAnyFlows && !existAnyGroups) {
                break;
            }
            log.info("Waiting to remove flows and groups from " +
                             "previous execution of {}...", appId.name());
            try {
                Thread.sleep(CLEAN_UP_DELAY);
            } catch (InterruptedException e) {
                log.error("Clean up interrupted!", e);
                Thread.currentThread().interrupt();
                return;
            }
            --retry;
        }
        log.debug("Clean up done ({})", appId.name());
    }
}
