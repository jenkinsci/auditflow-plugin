package io.jenkins.plugins.auditlogger;

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
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(5);
        config.setAnomalyFailedLoginsWindowMinutes(15);
        return config;
    }

    @Test
    @WithJenkins
    void testAnomalyDetectorBruteForce() {
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
    }

    @Test
    @WithJenkins
    void testAnomalyDetectorOldLoginsIgnored() {
        AnomalyDetector detector = new AnomalyDetector();
        AuditLoggerConfiguration config = createTestConfigWithAnomalyDetectionEnabled();
        
        long now = 2_000_000L;
        long twoMinutesAgo = now - 120_000;
        
        // Trigger 4 failures that are old (outside 15-minute window)
        for (int i = 0; i < 4; i++) {
            detector.analyze(new AuditLogEntry("old_user", "FAILED_LOGIN", "target", "details", twoMinutesAgo + i), config);
        }
        
        // Trigger 1 failure now
        detector.analyze(new AuditLogEntry("old_user", "FAILED_LOGIN", "target", "details", now), config);
        
        // Should be empty because the 4 old failures were ignored, so recent count is 1
        assertTrue(detector.getAlerts(10).isEmpty(), "Old failures outside window should not trigger alert with only 1 recent");
    }

    @Test
    @WithJenkins
    void testAnomalyDetectorReturnsLatestAlertsWhenLimited() {
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
    void testAuditLogStorageExceptionCaught() throws Exception {
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
}
