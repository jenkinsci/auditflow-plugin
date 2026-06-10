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
        detector = new AnomalyDetector() {
            @Override
            protected void sendEmail(jakarta.mail.internet.MimeMessage msg) throws Exception {
                // Do nothing to avoid Transport.send exception
            }
        };
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
    void testEmailAlertsConfiguration(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableEmailAlerts(true);
        // Include empty email to hit the !to.trim().isEmpty() false branch
        config.setAlertEmailAddresses("test@example.com, ");

        // Set admin address to null to hit the fallback branch
        hudson.tasks.Mailer.descriptor().setAdminAddress(null);



        long now = System.currentTimeMillis();
        // This will trigger an alert and attempt to send an email.
        detector.analyze(new AuditLogEntry("emailuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("emailuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size());
        

    }

    @Test
    void testNullConfigAndEmptyEmailAlerts(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(1);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        
        // Test with config == null
        detector.analyze(new AuditLogEntry("nullconfuser", "FAILED_LOGIN", "jenkins", "", System.currentTimeMillis()), null);
        
        // Test with empty email addresses
        config.setEnableEmailAlerts(true);
        config.setAlertEmailAddresses("   ");
        detector.analyze(new AuditLogEntry("emptyemailuser", "FAILED_LOGIN", "jenkins", "", System.currentTimeMillis()), config);

        // Test without JenkinsRule (causes exception or Mailer.descriptor() to be null)
        config.setAlertEmailAddresses("test@example.com");
        detector.analyze(new AuditLogEntry("nojenkinsuser", "FAILED_LOGIN", "jenkins", "", System.currentTimeMillis()), config);
    }
}
