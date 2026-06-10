package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AnomalyDetectorTest {

    private AnomalyDetector detector;

    @BeforeEach
    void setup() {
        detector = new AnomalyDetector();
    }

    @Test
    void testBruteForceLoginAnomalyIsDetected(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(3);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableEmailAlerts(false); // Test without email

        // Simulate 3 failed logins for the same user
        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("testuser", "FAILED_LOGIN", "jenkins", "", now), config);
        assertEquals(0, detector.getAlerts(10).size(), "Should not trigger yet");

        detector.analyze(new AuditLogEntry("testuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);
        assertEquals(0, detector.getAlerts(10).size(), "Should not trigger yet");

        detector.analyze(new AuditLogEntry("testuser", "FAILED_LOGIN", "jenkins", "", now + 2000), config);
        
        // On the 3rd failure, it should trigger
        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size(), "Should trigger alert");
        AnomalyDetector.AnomalyAlert alert = alerts.get(0);
        assertEquals(AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN, alert.type);
        assertEquals("testuser", alert.user);
    }

    @Test
    void testEmailAlertsConfiguration(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableEmailAlerts(true);
        config.setAlertEmailAddresses("test@example.com");

        long now = System.currentTimeMillis();
        // This will trigger an alert and attempt to send an email.
        // It should gracefully handle the absence of SMTP configuration without throwing exceptions.
        detector.analyze(new AuditLogEntry("emailuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("emailuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size());
        assertEquals("emailuser", alerts.get(0).user);
        
        // Additional configuration checks
        assertTrue(config.isEnableEmailAlerts());
        assertEquals("test@example.com", config.getAlertEmailAddresses());
    }
}
