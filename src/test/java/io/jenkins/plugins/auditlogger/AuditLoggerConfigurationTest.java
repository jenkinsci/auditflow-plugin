package io.jenkins.plugins.auditlogger;

import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.htmlunit.FailingHttpStatusCodeException;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.junit.jupiter.api.Test;
import org.kohsuke.stapler.verb.GET;

import java.time.ZoneId;
import java.util.List;

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
    void webhookDestinationsParseUnifiedTextareaAndLegacyFallback(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();

        configuration.setEnableWebhookAlerts(true);
        configuration.setWebhookDestinationsSpec("""
                generic|https://example.invalid/audit
                slack https://hooks.slack.invalid/services/A/B/C
                teams|https://example.invalid/teams
                """);

        List<AuditLoggerConfiguration.WebhookDestination> destinations = configuration.getEnabledWebhookDestinations();
        assertEquals(3, destinations.size());
        assertEquals("generic", destinations.get(0).getType());
        assertEquals("https://example.invalid/audit", destinations.get(0).getUrl());
        assertEquals("slack", destinations.get(1).getType());
        assertEquals("teams", destinations.get(2).getType());
        assertTrue(configuration.getWebhookDestinationsSpec().contains("slack|https://hooks.slack.invalid/services/A/B/C"));

        configuration.setWebhookDestinationsSpec("");
        configuration.setEnableWebhookAlerts(false);
        configuration.setEnableSlackAlerts(true);
        configuration.setSlackWebhookUrl("https://hooks.slack.invalid/services/legacy");

        List<AuditLoggerConfiguration.WebhookDestination> legacyDestinations = configuration.getEnabledWebhookDestinations();
        assertEquals(1, legacyDestinations.size());
        assertEquals("slack", legacyDestinations.get(0).getType());
        assertEquals("https://hooks.slack.invalid/services/legacy", legacyDestinations.get(0).getUrl());
        assertTrue(configuration.isEnableWebhookAlerts());
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
