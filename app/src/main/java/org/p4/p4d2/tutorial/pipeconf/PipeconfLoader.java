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

import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.pi.model.DefaultPiPipeconf;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiPipelineModel;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.p4runtime.model.P4InfoParser;
import org.onosproject.p4runtime.model.P4InfoParserException;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;

import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.BMV2_JSON;
import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.P4_INFO_TEXT;

/**
 * Component that builds and register the pipeconf at app activation.
 */
@Component(immediate = true)
public final class PipeconfLoader {

    private final Logger log = LoggerFactory.getLogger(getClass());

    public static final PiPipeconfId SRV6_PIPECONF_ID = new PiPipeconfId("org.p4.p4d2-srv6-tutorial");
    private static final String P4INFO_PATH = "/p4info.txt";
    private static final String BMV2_JSON_PATH = "/bmv2.json";


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private PiPipeconfService piPipeconfService;

    @Activate
    public void activate() {
        // Registers the pipeconf at component activation.
        try {
            piPipeconfService.register(buildPipeconf());
        } catch (P4InfoParserException e) {
            log.error("Unable to register " + SRV6_PIPECONF_ID, e);
        }
    }

    @Deactivate
    public void deactivate() {
        // Unregisters the pipeconf at component deactivation.
        try {
            piPipeconfService.remove(SRV6_PIPECONF_ID);
        } catch (IllegalStateException e) {
            log.warn("{} was not registered", SRV6_PIPECONF_ID);
        }
    }

    private PiPipeconf buildPipeconf() throws P4InfoParserException {

        final URL p4InfoUrl = PipeconfLoader.class.getResource(P4INFO_PATH);
        final URL bmv2JsonUrlUrl = PipeconfLoader.class.getResource(BMV2_JSON_PATH);
        final PiPipelineModel pipelineModel = P4InfoParser.parse(p4InfoUrl);

        return DefaultPiPipeconf.builder()
                .withId(SRV6_PIPECONF_ID)
                .withPipelineModel(pipelineModel)
                .addBehaviour(PiPipelineInterpreter.class, InterpreterImpl.class)
                .addBehaviour(Pipeliner.class, PipelinerImpl.class)
                .addExtension(P4_INFO_TEXT, p4InfoUrl)
                .addExtension(BMV2_JSON, bmv2JsonUrlUrl)
                .build();
    }
}
