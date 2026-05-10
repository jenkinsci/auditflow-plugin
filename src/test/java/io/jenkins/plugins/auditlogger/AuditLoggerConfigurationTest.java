package io.jenkins.plugins.auditlogger;

import hudson.util.ListBoxModel;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    }

    @Test
    void timezoneOptionsKeepSystemAndUtcAtTop(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();

        ListBoxModel items = configuration.doFillDisplayTimeZoneIdItems();

        assertEquals("SYSTEM", items.get(0).value);
        assertEquals("UTC", items.get(1).value);
    }

    @Test
    void popularTimezonesIncludeCompactPickerDefaults(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();

        assertTrue(configuration.getPopularDisplayTimeZoneIds().contains("UTC"));
        assertTrue(configuration.getPopularDisplayTimeZoneIds().contains("Asia/Kolkata"));
        assertTrue(configuration.getPopularDisplayTimeZoneIds().contains("America/New_York"));
        assertTrue(configuration.getPopularDisplayTimeZoneIds().contains("Europe/London"));
        assertTrue(configuration.getPopularDisplayTimeZoneIds().contains("Asia/Tokyo"));
    }
}