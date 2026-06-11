package io.jenkins.plugins.auditlogger;

import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class CoverageFixesTest {

    /**
     * Create a test configuration with anomaly detection enabled.
     */
    private AuditLoggerConfiguration createTestConfigWithAnomalyDetectionEnabled() {
        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(5);
        config.setAnomalyFailedLoginsWindowMinutes(15);
        return config;
    }

    @Test
    @WithJenkins
    void testAnomalyDetectorBruteForce(JenkinsRule j) {
        AnomalyDetector detector = new AnomalyDetector();
        AuditLoggerConfiguration config = createTestConfigWithAnomalyDetectionEnabled();
        
        // Trigger 4 failures - no alert
        for (int i = 0; i < 4; i++) {
            detector.analyze(new AuditLogEntry("test_user", "FAILED_LOGIN", "target", "details", 1_000L + i), config);
        }
        assertTrue(detector.getAlerts(10).isEmpty(), "First 4 failed logins should not trigger alert");
        
        // 5th failure triggers alert
        detector.analyze(new AuditLogEntry("test_user", "FAILED_LOGIN", "target", "details", 1_000L + 4), config);
        var alerts = detector.getAlerts(10);
        assertFalse(alerts.isEmpty(), "5th failed login should trigger alert");
        assertEquals(AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN, alerts.get(0).type, "Alert type should be BRUTE_FORCE_LOGIN");
        assertEquals("Multiple failed logins detected for \"test_user\" (5 attempts in 15 minutes).",
            alerts.get(0).details,
            "Alert details should use the operator-facing banner wording");
    }

    @Test
    @WithJenkins
    void testAnomalyDetectorOldLoginsIgnored(JenkinsRule j) {
        AnomalyDetector detector = new AnomalyDetector();
        AuditLoggerConfiguration config = createTestConfigWithAnomalyDetectionEnabled();
        
        long now = 2_000_000L;
        long sixteenMinutesAgo = now - (16 * 60_000L);
        
        // Trigger 4 failures that are old (outside 15-minute window)
        for (int i = 0; i < 4; i++) {
            detector.analyze(new AuditLogEntry("old_user", "FAILED_LOGIN", "target", "details", sixteenMinutesAgo + i), config);
        }
        
        // Trigger 1 failure now
        detector.analyze(new AuditLogEntry("old_user", "FAILED_LOGIN", "target", "details", now), config);
        
        // Should be empty because the 4 old failures were ignored, so recent count is 1
        assertTrue(detector.getAlerts(10).isEmpty(), "Old failures outside window should not trigger alert with only 1 recent");
    }

    @Test
    @WithJenkins
    void testAnomalyDetectorReturnsLatestAlertsWhenLimited(JenkinsRule j) {
        AnomalyDetector detector = new AnomalyDetector();
        AuditLoggerConfiguration config = createTestConfigWithAnomalyDetectionEnabled();

        // Add 5 failures for user-one (triggers alert)
        for (int i = 0; i < 5; i++) {
            detector.analyze(new AuditLogEntry("user-one", "FAILED_LOGIN", "target", "details", 1_000L + i), config);
        }
        // Add 5 failures for user-two (triggers another alert)
        for (int i = 0; i < 5; i++) {
            detector.analyze(new AuditLogEntry("user-two", "FAILED_LOGIN", "target", "details", 2_000L + i), config);
        }

        var alerts = detector.getAlerts(1);
        assertEquals(1, alerts.size(), "Should return exactly 1 alert when limit is 1");
        assertEquals("user-two", alerts.get(0).user, "Should return the latest alert");
    }

    @Test
    @WithJenkins
    void testAnomalyDetectorCanTriggerAgainForSameUser(JenkinsRule j) {
        AnomalyDetector detector = new AnomalyDetector();
        AuditLoggerConfiguration config = createTestConfigWithAnomalyDetectionEnabled();

        for (int i = 0; i < 5; i++) {
            detector.analyze(new AuditLogEntry("repeat-user", "FAILED_LOGIN", "target", "details", 1_000L + i), config);
        }
        for (int i = 0; i < 5; i++) {
            detector.analyze(new AuditLogEntry("repeat-user", "FAILED_LOGIN", "target", "details", 2_000L + i), config);
        }

        var alerts = detector.getAlerts(10);
        assertEquals(2, alerts.size(), "Crossing the threshold again should generate another alert for the same user");
        assertEquals("repeat-user", alerts.get(1).user, "The repeated alert should still identify the same user");
    }


    @Test
    @WithJenkins
    void testAuditLogStorageExceptionCaught(JenkinsRule j) throws Exception {
        // Inject an anonymous anomaly detector that throws an exception
        AnomalyDetector mockDetector = new AnomalyDetector() {
            @Override
            public void analyze(AuditLogEntry entry, AuditLoggerConfiguration config) {
                throw new RuntimeException("Simulated exception");
            }
        };
        
        AuditLogStorage storage = AuditLogStorage.getInstance();
        Field detectorField = AuditLogStorage.class.getDeclaredField("anomalyDetector");
        detectorField.setAccessible(true);
        AnomalyDetector original = (AnomalyDetector) detectorField.get(storage);
        
        try {
            detectorField.set(storage, mockDetector);
            
            // This should not throw; the exception should be caught in addEntry
            AuditLogEntry entry = new AuditLogEntry("user", "action", "target", "details");
            storage.addEntry(entry);
            
            // Test passed if no exception was thrown
            assertTrue(true, "addEntry should handle detector exceptions gracefully");
            
        } finally {
            // Restore original detector
            detectorField.set(storage, original);
        }
    }

    @Test
    void testAuditLoggerConfigurationCoverage(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        
        // Coverage for setEnableAlertEngine
        config.setEnableAlertEngine(true);
        assertTrue(config.isEnableAlertEngine());
        
        // Coverage for getAlertEmailAddresses null branch
        config.setAlertEmailAddresses(null);
        assertEquals("", config.getAlertEmailAddresses());
    }

    @Test
    @WithJenkins
    void testConfigureWebhookFieldsCoverage(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();

        // Exercise the configure() JSON path for webhook fields (lines 226-227)
        net.sf.json.JSONObject json = new net.sf.json.JSONObject();
        json.put("enableWebhookAlerts", true);
        json.put("webhookUrl", "https://hooks.example.com/test");
        config.configure((org.kohsuke.stapler.StaplerRequest2) null, json);

        assertTrue(config.isEnableWebhookAlerts(), "enableWebhookAlerts should be true after configure");
        assertEquals("https://hooks.example.com/test", config.getWebhookUrl(), "webhookUrl should be set after configure");
    }

    @Test
    @WithJenkins
    void testGetWebhookUrlNullBranch(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setWebhookUrl(null);
        assertEquals("", config.getWebhookUrl(), "getWebhookUrl should return empty string when null");
    }
}
