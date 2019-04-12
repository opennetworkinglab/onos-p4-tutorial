package org.p4.p4d2.tutorial;

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
 * A component which register the Srv6DeviceConfig config.
 */
@Component(immediate = true)
public class Srv6DeviceConfigManager {
    private static final Logger log =
            LoggerFactory.getLogger(Srv6DeviceConfigManager.class.getName());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry registry;

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
        registry.registerConfigFactory(srv6ConfigFactory);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        registry.unregisterConfigFactory(srv6ConfigFactory);
        log.info("Stopped");
    }
}
