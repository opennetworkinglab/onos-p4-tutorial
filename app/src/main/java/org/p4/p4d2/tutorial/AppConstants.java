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

import org.onosproject.net.pi.model.PiPipeconfId;

public class AppConstants {

    public static final String APP_PREFIX = "org.p4.srv6-tutorial";
    public static final PiPipeconfId SRV6_PIPECONF_ID = new PiPipeconfId("org.p4.srv6-tutorial");

    public static final int DEFAULT_FLOW_RULE_PRIORITY = 10;
    public static final int INITIAL_SETUP_DELAY = 5; // Seconds.
}
