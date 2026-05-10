package io.jenkins.plugins.auditlogger;

import java.lang.reflect.Method;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuditLoggerManagementLinkInsightsRegressionTest {

    @Test
    @SuppressWarnings("unchecked")
    void buildAnomalyConfigProvidesStableInsightThresholdDefaults() throws Exception {
        Method buildAnomalyConfig = AuditLoggerManagementLink.class
                .getDeclaredMethod("buildAnomalyConfig", AuditLoggerConfiguration.class);
        buildAnomalyConfig.setAccessible(true);

        Map<String, Object> config = (Map<String, Object>) buildAnomalyConfig.invoke(null, new Object[] { null });

        assertEquals(5, config.get("failedLoginsThreshold"));
        assertEquals(3, config.get("credentialChangesThreshold"));
        assertEquals(3, config.get("pluginChangesThreshold"));
        assertEquals(5, config.get("globalConfigChangesThreshold"));
        assertEquals(1, config.get("jobConfigChangesThreshold"));
        assertEquals(1, config.get("securityConfigChangesThreshold"));
        assertEquals(5, config.get("buildFailuresThreshold"));
    }
}