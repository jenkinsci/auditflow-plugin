package io.jenkins.plugins.auditlogger;

import hudson.util.ListBoxModel;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditLoggerConfigurationTest {

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
        assertEquals("UTC", configuration.getDisplayTimeZoneId());

        configuration.setDisplayTimeZoneId("America/New_York");
        assertEquals("America/New_York", configuration.getDisplayTimeZoneId());
    }

    @Test
    void timezoneOptionsMatchSupportedIanaValues(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();

        ListBoxModel items = configuration.doFillDisplayTimeZoneIdItems();

        assertEquals(4, items.size());
        assertEquals("Asia/Kolkata", items.get(0).value);
        assertEquals("Europe/London", items.get(1).value);
        assertEquals("America/New_York", items.get(2).value);
        assertEquals("UTC", items.get(3).value);
    }

    @Test
    void timezoneOptionsJsonIncludesOffsetMetadata(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();
        JSONArray options = JSONArray.fromObject(configuration.getAvailableDisplayTimeZonesJson());

        assertEquals(4, options.size());

        JSONObject first = options.getJSONObject(0);
        assertEquals("Asia/Kolkata", first.getString("id"));
        assertEquals("Asia/Kolkata", first.getString("label"));
        assertTrue(first.getString("offset").startsWith("UTC+"));

        JSONObject utc = options.getJSONObject(3);
        assertEquals("UTC", utc.getString("id"));
        assertFalse(utc.getString("offset").isBlank());
    }
}