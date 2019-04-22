package org.p4.p4d2.tutorial;

import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.basics.SubjectFactories;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.p4.p4d2.tutorial.common.Srv6DeviceConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A component which among other things registers the Srv6DeviceConfig to the
 * netcfg subsystem.
 */
@Component(immediate = true)
public class MainComponent {
    private static final Logger log =
            LoggerFactory.getLogger(MainComponent.class.getName());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry registry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private ComponentConfigService compCfgService;

    private ConfigFactory<DeviceId, Srv6DeviceConfig> srv6ConfigFactory =
            new ConfigFactory<DeviceId, Srv6DeviceConfig>(
                    SubjectFactories.DEVICE_SUBJECT_FACTORY, Srv6DeviceConfig.class, Srv6DeviceConfig.CONFIG_KEY) {
                @Override
                public Srv6DeviceConfig createConfig() {
                    return new Srv6DeviceConfig();
                }
            };

    @Activate
    protected void activate() {
        compCfgService.preSetProperty("org.onosproject.net.flow.impl.FlowRuleManager",
                                      "fallbackFlowPollFrequency", "4", false);
        compCfgService.preSetProperty("org.onosproject.net.group.impl.GroupManager",
                                      "fallbackGroupPollFrequency", "3", false);
        compCfgService.preSetProperty("org.onosproject.provider.host.impl.HostLocationProvider",
                                      "requestIpv6ND", "true", false);

        registry.registerConfigFactory(srv6ConfigFactory);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        registry.unregisterConfigFactory(srv6ConfigFactory);
        log.info("Stopped");
    }
}
