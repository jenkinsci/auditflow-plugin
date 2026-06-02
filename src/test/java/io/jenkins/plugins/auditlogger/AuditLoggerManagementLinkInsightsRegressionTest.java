package io.jenkins.plugins.auditlogger;

import java.lang.reflect.Method;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

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

    @Test
    void bulkPluginUpdateShouldCountEachPluginSeparately() {
        long now = System.currentTimeMillis();

        // simulate a single plugin update and a bulk update with multiple plugins
        AuditLogEntry singleUpdate = new AuditLogEntry("admin", "PLUGIN_UPDATED", "git", "", now);
        AuditLogEntry bulkUpdate = new AuditLogEntry("admin", "PLUGIN_UPDATED", "matrix-auth,role-strategy,credentials", "", now);
        AuditLogEntry bulkInstall = new AuditLogEntry("admin", "PLUGIN_INSTALLED", "docker-workflow,pipeline-model-definition", "", now);

        List<AuditLogEntry> entries = Arrays.asList(singleUpdate, bulkUpdate, bulkInstall);

        List<Map<String, Object>> insights = AuditLoggerManagementLink.buildInsights(
                entries, null, ZoneOffset.UTC);

        Map<String, Object> pluginInsight = insights.stream()
                .filter(i -> "Plugin changes".equals(i.get("text")))
                .findFirst()
                .orElseThrow(() -> new AssertionError("expected a Plugin changes insight"));

        // 1 + 3 + 2 = 6 total plugins across all entries
        assertEquals(6, pluginInsight.get("count"));
    }
}