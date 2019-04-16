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

package org.p4.p4d2.tutorial.pipeconf;

import com.google.common.collect.ImmutableBiMap;
import com.google.common.collect.ImmutableList;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.stream.Collectors.toList;
import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.onosproject.net.PortNumber.CONTROLLER;
import static org.onosproject.net.PortNumber.FLOOD;
import static org.onosproject.net.flow.instructions.Instruction.Type.OUTPUT;
import static org.onosproject.net.flow.instructions.Instructions.OutputInstruction;
import static org.onosproject.net.pi.model.PiPacketOperationType.PACKET_OUT;
import static org.p4.p4d2.tutorial.AppConstants.CPU_PORT_ID;
import static org.p4.p4d2.tutorial.P4InfoConstants.EGRESS_PORT;
import static org.p4.p4d2.tutorial.P4InfoConstants.FABRIC_INGRESS_ACL;
import static org.p4.p4d2.tutorial.P4InfoConstants.FABRIC_INGRESS_CLONE_TO_CPU;
import static org.p4.p4d2.tutorial.P4InfoConstants.FABRIC_INGRESS_DROP;
import static org.p4.p4d2.tutorial.P4InfoConstants.HDR_ETHERNET_DST_ADDR;
import static org.p4.p4d2.tutorial.P4InfoConstants.HDR_ETHERNET_ETHER_TYPE;
import static org.p4.p4d2.tutorial.P4InfoConstants.HDR_ETHERNET_SRC_ADDR;
import static org.p4.p4d2.tutorial.P4InfoConstants.HDR_IPV6_DST_ADDR;
import static org.p4.p4d2.tutorial.P4InfoConstants.HDR_STANDARD_METADATA_INGRESS_PORT;
import static org.p4.p4d2.tutorial.P4InfoConstants.INGRESS_PORT;
import static org.p4.p4d2.tutorial.P4InfoConstants.NO_ACTION;


/**
 * Interpreter implementation.
 */
public class InterpreterImpl extends AbstractHandlerBehaviour
        implements PiPipelineInterpreter {

    private static final int PORT_BITWIDTH = 9;

    private static final ImmutableBiMap<Criterion.Type, PiMatchFieldId> CRITERION_MAP =
            new ImmutableBiMap.Builder<Criterion.Type, PiMatchFieldId>()
                    .put(Criterion.Type.IN_PORT, HDR_STANDARD_METADATA_INGRESS_PORT)
                    .put(Criterion.Type.ETH_DST, HDR_ETHERNET_DST_ADDR)
                    .put(Criterion.Type.ETH_SRC, HDR_ETHERNET_SRC_ADDR)
                    .put(Criterion.Type.ETH_TYPE, HDR_ETHERNET_ETHER_TYPE)
                    .put(Criterion.Type.IPV6_DST, HDR_IPV6_DST_ADDR)
                    .build();

    @Override
    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId)
            throws PiInterpreterException {
        if (!piTableId.equals(FABRIC_INGRESS_ACL)) {
            throw new PiInterpreterException(
                    "Treatment mapping not supported for table " + piTableId);
        }

        if (treatment.allInstructions().isEmpty()) {
            // Zero instructions means drop.
            return PiAction.builder().withId(FABRIC_INGRESS_DROP).build();
        } else if (treatment.allInstructions().size() > 1) {
            // We understand treatments with only 1 instruction.
            throw new PiInterpreterException("Treatment has too many instructions");
        }

        Instruction instruction = treatment.allInstructions().get(0);
        switch (instruction.type()) {
            case OUTPUT:
                PortNumber port = ((OutputInstruction) instruction).port();
                if (port.equals(CONTROLLER)) {
                    // FIXME: modify hostprovider and packet requests to install
                    //  clone to CPU rules.
                    final PiActionId actionId = FABRIC_INGRESS_CLONE_TO_CPU;
                    // final PiActionId actionId = treatment.clearedDeferred()
                    //         ? FABRIC_INGRESS_PUNT_TO_CPU
                    //         : FABRIC_INGRESS_CLONE_TO_CPU;
                    return PiAction.builder().withId(actionId).build();
                }
                break;
            case NOACTION:
                return PiAction.builder().withId(NO_ACTION).build();
            default:
                break;
        }
        throw new PiInterpreterException(format(
                "Treatment mapping not supported for instruction %s", instruction));
    }

    @Override
    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet)
            throws PiInterpreterException {
        TrafficTreatment treatment = packet.treatment();

        // Packet-out in srv6.p4 supports only setting the output port,
        // i.e. OUTPUT instructions.
        List<OutputInstruction> outInstructions = treatment
                .allInstructions()
                .stream()
                .filter(i -> i.type().equals(OUTPUT))
                .map(i -> (OutputInstruction) i)
                .collect(toList());

        if (treatment.allInstructions().size() != outInstructions.size()) {
            // There are other instructions that are not of type OUTPUT.
            throw new PiInterpreterException("Treatment not supported: " + treatment);
        }

        ImmutableList.Builder<PiPacketOperation> builder = ImmutableList.builder();
        for (OutputInstruction outInst : outInstructions) {
            if (outInst.port().isLogical() && !outInst.port().equals(FLOOD)) {
                throw new PiInterpreterException(format(
                        "Packet-out on logical port '%s' not supported", outInst.port()));
            } else if (outInst.port().equals(FLOOD)) {
                // To emulate flooding, we create a packet-out operation for
                // each switch port.
                final DeviceService deviceService = handler().get(DeviceService.class);
                for (Port port : deviceService.getPorts(packet.sendThrough())) {
                    builder.add(createPacketOp(packet.data(), port.number().toLong()));
                }
            } else {
                // Singleton port.
                builder.add(createPacketOp(packet.data(), outInst.port().toLong()));
            }
        }
        return builder.build();
    }

    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId)
            throws PiInterpreterException {

        Ethernet ethPkt;
        try {
            ethPkt = Ethernet.deserializer().deserialize(
                    packetIn.data().asArray(), 0, packetIn.data().size());
        } catch (DeserializationException dex) {
            throw new PiInterpreterException(dex.getMessage());
        }

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadata = packetIn.metadatas()
                .stream().filter(m -> m.id().equals(INGRESS_PORT))
                .findFirst();

        if (packetMetadata.isPresent()) {
            ImmutableByteSequence portByteSequence = packetMetadata.get().value();
            short s = portByteSequence.asReadOnlyBuffer().getShort();
            ConnectPoint receivedFrom = new ConnectPoint(deviceId, PortNumber.portNumber(s));
            ByteBuffer rawData = ByteBuffer.wrap(packetIn.data().asArray());
            return new DefaultInboundPacket(receivedFrom, ethPkt, rawData);
        } else {
            throw new PiInterpreterException(format(
                    "Missing metadata '%s' in packet-in received from '%s': %s",
                    INGRESS_PORT, deviceId, packetIn));
        }
    }

    private PiPacketOperation createPacketOp(ByteBuffer data, long portNumber)
            throws PiInterpreterException {
        PiPacketMetadata metadata = createPacketMetadata(portNumber);
        return PiPacketOperation.builder()
                .withType(PACKET_OUT)
                .withData(copyFrom(data))
                .withMetadatas(ImmutableList.of(metadata))
                .build();
    }

    private PiPacketMetadata createPacketMetadata(long portNumber) throws PiInterpreterException {
        try {
            return PiPacketMetadata.builder()
                    .withId(EGRESS_PORT)
                    .withValue(copyFrom(portNumber).fit(PORT_BITWIDTH))
                    .build();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            throw new PiInterpreterException(format(
                    "Port number %d too big, %s", portNumber, e.getMessage()));
        }
    }

    @Override
    public Optional<Integer> mapLogicalPortNumber(PortNumber port) {
        if (CONTROLLER.equals(port)) {
            return Optional.of(CPU_PORT_ID);
        } else {
            return Optional.empty();
        }
    }

    @Override
    public Optional<PiMatchFieldId> mapCriterionType(Criterion.Type type) {
        return Optional.ofNullable(CRITERION_MAP.get(type));
    }

    @Override
    public Optional<Criterion.Type> mapPiMatchFieldId(PiMatchFieldId headerFieldId) {
        return Optional.ofNullable(CRITERION_MAP.inverse().get(headerFieldId));
    }

    @Override
    public Optional<PiTableId> mapFlowRuleTableId(int flowRuleTableId) {
        return Optional.empty();
    }

    @Override
    public Optional<Integer> mapPiTableId(PiTableId piTableId) {
        return Optional.empty();
    }
}
