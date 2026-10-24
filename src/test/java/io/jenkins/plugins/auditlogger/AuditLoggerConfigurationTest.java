package io.jenkins.plugins.auditlogger;

import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.html.HtmlPage;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.junit.jupiter.api.Test;
import org.kohsuke.stapler.verb.GET;

import java.time.ZoneId;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditLoggerConfigurationTest {

    @Test
    void freshConfigurationDefaultsToSystemTimezone(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();

        assertEquals(AuditLoggerConfiguration.canonicalizeTimeZoneId(ZoneId.systemDefault().getId()),
            configuration.getDisplayTimeZoneId());
    }

    @Test
    void settersClampValuesAndSanitizeDisplayTimezone(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();

        configuration.setLogRetentionDays(-10);
        configuration.setMaxLogFileSizeMB(5_000);
        configuration.setStartupGracePeriodSeconds(1);
        configuration.setBatchWriteSize(0);
        configuration.setBatchFlushIntervalSeconds(999);
        configuration.setDisplayTimeZoneId("not/a-time-zone");

        assertEquals(0, configuration.getLogRetentionDays());
        assertEquals(1_024, configuration.getMaxLogFileSizeMB());
        assertEquals(5, configuration.getStartupGracePeriodSeconds());
        assertEquals(1, configuration.getBatchWriteSize());
        assertEquals(300, configuration.getBatchFlushIntervalSeconds());
        assertEquals("UTC", configuration.getDisplayTimeZoneId());

        configuration.setDisplayTimeZoneId("Europe/Berlin");
        assertEquals("Europe/Berlin", configuration.getDisplayTimeZoneId());

        configuration.setDisplayTimeZoneId("America/New_York");
        assertEquals("America/New_York", configuration.getDisplayTimeZoneId());
    }

    @Test
    void timezoneOptionsMatchSupportedIanaValues(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();

        ListBoxModel items = configuration.doFillDisplayTimeZoneIdItems();

        assertTrue(items.size() > 100);
        // Verify list contains known timezones
        assertTrue(items.stream().anyMatch(option -> "UTC".equals(option.value)));
        assertTrue(items.stream().anyMatch(option -> "Europe/Berlin".equals(option.value)));
        // Verify first item is not empty
        assertNotNull(items.get(0).value);
        assertFalse(items.get(0).value.isEmpty());
    }

    @Test
    void timezoneOptionsJsonIncludesOffsetMetadata(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();
        JSONArray options = JSONArray.fromObject(configuration.getAvailableDisplayTimeZonesJson());

        assertTrue(options.size() > 100);

        // Verify first item has required fields
        JSONObject first = options.getJSONObject(0);
        assertNotNull(first.getString("id"));
        assertFalse(first.getString("id").isEmpty());
        assertTrue(first.getString("label").length() > 0);
        assertFalse(first.getString("offset").isBlank());

        JSONObject utc = findOption(options, "UTC");
        assertEquals("UTC", utc.getString("id"));
        assertTrue(utc.getString("label").contains("UTC"));
        assertFalse(utc.getString("offset").isBlank());

        JSONObject berlin = findOption(options, "Europe/Berlin");
        assertEquals("Europe/Berlin", berlin.getString("id"));
        assertEquals("Europe/Berlin", berlin.getString("label"));

        JSONObject kolkata = findOption(options, "Asia/Kolkata");
        assertTrue(kolkata.getString("label").contains("India Standard Time"));
        assertTrue(kolkata.getString("searchText").contains("Chennai"));
        assertTrue(kolkata.getString("searchText").contains("India Standard Time"));
    }

    @Test
    void displayTimeZoneItemsEndpointIsAnnotatedGet() throws Exception {
        assertTrue(AuditLoggerConfiguration.class
                .getMethod("doFillDisplayTimeZoneIdItems")
                .isAnnotationPresent(GET.class));
    }

    @Test
    void displayTimeZoneItemsEndpointRequiresAdminPermission(JenkinsRule j) {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.READ)
                .everywhere()
                .toEveryone());

        JenkinsRule.WebClient webClient = j.createWebClient();
        FailingHttpStatusCodeException failure = assertThrows(FailingHttpStatusCodeException.class,
                () -> webClient.goTo(
                        "descriptorByName/io.jenkins.plugins.auditlogger.AuditLoggerConfiguration/fillDisplayTimeZoneIdItems",
                        "application/json"));

        assertEquals(403, failure.getStatusCode());
    }

    @Test
    void webhookUrlSetterSupportsSimpleSingleDestination(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();

        configuration.setEnableWebhookAlerts(true);
        configuration.setWebhookUrl("https://example.invalid/audit");
        assertTrue(configuration.isEnableWebhookAlerts());
        assertEquals("https://example.invalid/audit", configuration.getWebhookUrl());
    }

    @Test
    void configureJsonSupportsOptionalBlockPayloads(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration configuration = new AuditLoggerConfiguration();
        JSONObject json = new JSONObject();
        JSONObject emailAlerts = new JSONObject();
        JSONObject webhookAlerts = new JSONObject();
        JSONObject failedLoginDetection = new JSONObject();
        JSONObject dashboardStats = new JSONObject();

        emailAlerts.put("alertEmailAddresses", "secops@example.com, admins@example.com");
        webhookAlerts.put("webhookUrl", "https://hooks.slack.com/services/T000/B000/XXXX");
        failedLoginDetection.put("anomalyFailedLoginsThreshold", 4);
        failedLoginDetection.put("anomalyFailedLoginsWindowMinutes", 12);
        dashboardStats.put("showMetricTotal", true);
        dashboardStats.put("showMetricLogins", false);
        dashboardStats.put("showMetricFailedLogins", true);
        dashboardStats.put("showMetricBuilds", true);
        dashboardStats.put("showMetricJobs", false);
        dashboardStats.put("showMetricConfig", true);

        json.put("enableEmailAlerts", emailAlerts);
        json.put("enableWebhookAlerts", webhookAlerts);
        json.put("anomalyFailedLogins", failedLoginDetection);
        json.put("enableDashboardStats", dashboardStats);

        configuration.configure((org.kohsuke.stapler.StaplerRequest2) null, json);

        assertTrue(configuration.isEnableEmailAlerts());
        assertEquals("secops@example.com, admins@example.com", configuration.getAlertEmailAddresses());
        assertTrue(configuration.isEnableWebhookAlerts());
        assertEquals("https://hooks.slack.com/services/T000/B000/XXXX", configuration.getWebhookUrl());
        assertTrue(configuration.isAnomalyFailedLogins());
        assertEquals(4, configuration.getAnomalyFailedLoginsThreshold());
        assertEquals(12, configuration.getAnomalyFailedLoginsWindowMinutes());
        assertTrue(configuration.isEnableDashboardStats());
        assertTrue(configuration.isShowMetricTotal());
        assertFalse(configuration.isShowMetricLogins());
        assertTrue(configuration.isShowMetricFailedLogins());
        assertTrue(configuration.isShowMetricBuilds());
        assertFalse(configuration.isShowMetricJobs());
        assertTrue(configuration.isShowMetricConfig());
    }

    @Test
    void configurePageShowsPhaseOneSectionsAndWebhookGuidance(JenkinsRule j) throws Exception {
        JenkinsRule.WebClient webClient = j.createWebClient();
        HtmlPage page = webClient.goTo("configure");
        String html = page.getWebResponse().getContentAsString();

        assertTrue(html.contains("Event Logging Controls"));
        assertTrue(html.contains("Operational Monitoring &amp; Export"));
        assertTrue(html.contains("Display Time Zone"));
        assertTrue(html.contains("Notifications"));
        assertTrue(html.contains("Export and Integrations"));
        assertTrue(html.contains("Advanced"));
        assertTrue(html.contains("Enter a valid HTTP webhook endpoint"));
        assertTrue(html.contains("https://hooks.slack.com/services/T000/B000/XXXX"));
        assertTrue(html.contains("/auditflow/api"));

        int eventLoggingIndex = html.indexOf("Event Logging Controls");
        int anomalyIndex = html.indexOf("Security Anomaly Detection");
        int notificationsIndex = html.indexOf("Anomaly Alert Notifications");
        int operationalIndex = html.indexOf("Operational Monitoring &amp; Export");
        int timeZoneIndex = html.indexOf("Display Time Zone");
        int exportIndex = html.indexOf("Export and Integrations");

        assertTrue(eventLoggingIndex < anomalyIndex, "Event Logging before Anomaly Detection");
        assertTrue(anomalyIndex < notificationsIndex, "Anomaly Detection contains Notifications");
        assertTrue(notificationsIndex < operationalIndex, "Notifications before Operational Monitoring");
        assertTrue(operationalIndex < timeZoneIndex, "Operational Monitoring before Display Time Zone");
        assertTrue(timeZoneIndex < exportIndex, "Display Time Zone before Export and Integrations");
    }

    @Test
    void multiWebhookConfigurationJsonBinding(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration configuration = new AuditLoggerConfiguration();
        JSONObject json = new JSONObject();
        JSONObject webhookAlerts = new JSONObject();
        webhookAlerts.put("webhookUrl", "https://default.example.com/webhook");

        JSONObject multiWebhook = new JSONObject();
        net.sf.json.JSONArray endpoints = new net.sf.json.JSONArray();

        JSONObject ep1 = new JSONObject();
        ep1.put("name", "SecOps Slack");
        ep1.put("channel", "#secops-urgent");
        ep1.put("webhookUrl", "https://hooks.slack.com/services/T00/B00/SEC");
        ep1.put("enabled", true);
        ep1.put("scope", "CRITICAL_LOGS_ONLY");
        ep1.put("minSeverity", "CRITICAL");
        ep1.put("actionFilter", "SCRIPT_CONSOLE_ACCESS");
        endpoints.add(ep1);

        JSONObject ep2 = new JSONObject();
        ep2.put("name", "DevOps Alerts");
        ep2.put("channel", "#devops");
        ep2.put("webhookUrl", "https://hooks.slack.com/services/T00/B00/DEV");
        ep2.put("enabled", true);
        ep2.put("scope", "ALL_ALERTS");
        ep2.put("minSeverity", "HIGH");
        endpoints.add(ep2);

        multiWebhook.put("webhookEndpoints", endpoints);
        webhookAlerts.put("enableMultiWebhook", multiWebhook);
        json.put("enableWebhookAlerts", webhookAlerts);

        configuration.configure((org.kohsuke.stapler.StaplerRequest2) null, json);

        assertTrue(configuration.isEnableWebhookAlerts());
        assertEquals("https://default.example.com/webhook", configuration.getWebhookUrl());
        assertTrue(configuration.isEnableMultiWebhook());
        assertEquals(2, configuration.getWebhookEndpoints().size());

        WebhookEndpoint endpoint1 = configuration.getWebhookEndpoints().get(0);
        assertEquals("SecOps Slack", endpoint1.getName());
        assertEquals("#secops-urgent", endpoint1.getChannel());
        assertEquals("CRITICAL_LOGS_ONLY", endpoint1.getScope());
        assertEquals("CRITICAL", endpoint1.getMinSeverity());
        assertEquals("SCRIPT_CONSOLE_ACCESS", endpoint1.getActionFilter());
    }

    @Test
    void resolveActiveEndpointsWithProgressiveDisclosure(JenkinsRule j) {
        AuditLoggerConfiguration configuration = new AuditLoggerConfiguration();

        // 1. When webhooks are disabled entirely
        configuration.setEnableWebhookAlerts(false);
        configuration.setWebhookUrl("https://legacy.example.com/webhook");
        assertTrue(configuration.resolveActiveEndpoints("ANOMALY", "HIGH", "TEST").isEmpty());

        // 2. Single webhook mode (multi-webhook disabled)
        configuration.setEnableWebhookAlerts(true);
        configuration.setEnableMultiWebhook(false);
        var singleTargets = configuration.resolveActiveEndpoints("ANOMALY", "HIGH", "TEST");
        assertEquals(1, singleTargets.size());
        assertEquals("https://legacy.example.com/webhook", singleTargets.get(0).getPlainWebhookUrl());

        // Low severity doesn't meet default HIGH threshold on single endpoint
        assertTrue(configuration.resolveActiveEndpoints("ANOMALY", "LOW", "TEST").isEmpty());

        // 3. Multi-webhook mode enabled
        configuration.setEnableMultiWebhook(true);
        WebhookEndpoint epCrit = new WebhookEndpoint("SecOps", "https://hooks.slack.com/secops");
        epCrit.setScope("CRITICAL_LOGS_ONLY");
        epCrit.setMinSeverity("CRITICAL");
        epCrit.setActionFilter("SCRIPT_CONSOLE_ACCESS");

        WebhookEndpoint epAll = new WebhookEndpoint("General", "https://hooks.slack.com/general");
        epAll.setScope("ALL_ALERTS");
        epAll.setMinSeverity("HIGH");

        configuration.setWebhookEndpoints(java.util.List.of(epCrit, epAll));

        // Direct audit log with SCRIPT_CONSOLE_ACCESS & CRITICAL matches BOTH epCrit and epAll
        var targets = configuration.resolveActiveEndpoints("AUDIT_LOG", "CRITICAL", "SCRIPT_CONSOLE_ACCESS");
        assertEquals(2, targets.size());

        // Anomaly alert with HIGH severity matches ONLY epAll
        var anomalyTargets = configuration.resolveActiveEndpoints("ANOMALY", "HIGH", "FAILED_LOGINS");
        assertEquals(1, anomalyTargets.size());
        assertEquals("General", anomalyTargets.get(0).getName());

        // Direct audit log with USER_DELETED & CRITICAL matches ONLY epAll (because epCrit actionFilter is SCRIPT_CONSOLE_ACCESS)
        var userDelTargets = configuration.resolveActiveEndpoints("AUDIT_LOG", "CRITICAL", "USER_DELETED");
        assertEquals(1, userDelTargets.size());
        assertEquals("General", userDelTargets.get(0).getName());
    }

    @Test
    void testWebhookValidation(JenkinsRule j) {
        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        assertEquals(hudson.util.FormValidation.Kind.ERROR, config.doTestWebhookUrl("").kind);
        assertEquals(hudson.util.FormValidation.Kind.ERROR, config.doTestWebhookUrl("ftp://bad.com").kind);
    }

    private static JSONObject findOption(JSONArray options, String id) {
        for (int index = 0; index < options.size(); index++) {
            JSONObject option = options.getJSONObject(index);
            if (id.equals(option.getString("id"))) {
                return option;
            }
        }
        throw new AssertionError("Missing time zone option: " + id);
    }
}
