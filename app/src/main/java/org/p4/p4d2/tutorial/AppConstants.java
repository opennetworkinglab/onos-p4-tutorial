package org.p4.p4d2.tutorial;

import org.onosproject.net.pi.model.PiPipeconfId;

public class AppConstants {

    public static final String APP_PREFIX = "org.p4.srv6-tutorial";
    public static final PiPipeconfId SRV6_PIPECONF_ID = new PiPipeconfId("org.p4.srv6-tutorial");

    public static final int DEFAULT_FLOW_RULE_PRIORITY = 10;
    public static final int INITIAL_SETUP_DELAY = 5; // Seconds.

    public static final int P4RUNTIME_DEVICE_ID = 1;
    public static final int CPU_PORT_ID = 255;
    public static final int CPU_CLONE_SESSION_ID = 99;
}
