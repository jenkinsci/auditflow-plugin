package io.jenkins.plugins.auditlogger;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class AnomalyDetectorPhase2Test {

    private AnomalyDetector detector;

    @BeforeEach
    void setup() {
        detector = new AnomalyDetector();
    }

    @Test
    void testUnusualIpDetection(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyUnusualIp(true);

        long now = System.currentTimeMillis();
        AuditLogEntry entry1 = AuditLogEntry.withAuth("alice", "LOGIN", "Jenkins", "Login from primary IP", "192.168.1.10", "form");
        detector.analyze(entry1, config);
        assertEquals(0, detector.getAlerts(10).size(), "First IP establishes baseline, no alert");

        AuditLogEntry entry2 = AuditLogEntry.withAuth("alice", "LOGIN", "Jenkins", "Login from secondary IP", "10.0.0.99", "form");
        detector.analyze(entry2, config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size(), "Should trigger UNUSUAL_IP alert");
        assertEquals(AnomalyDetector.AnomalyType.UNUSUAL_IP, alerts.get(0).type);
        assertEquals("alice", alerts.get(0).user);
        assertTrue(alerts.get(0).details.contains("10.0.0.99"));
    }

    @Test
    void testMultiIpLoginDetection(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyMultiIpLogin(true);
        config.setAnomalyMultiIpLoginThreshold(2);
        config.setAnomalyMultiIpLoginWindowMinutes(15);

        long now = System.currentTimeMillis();
        AuditLogEntry entry1 = AuditLogEntry.withAuth("bob", "LOGIN", "Jenkins", "Login 1", "192.168.1.1", "form");
        detector.analyze(entry1, config);
        assertEquals(0, detector.getAlerts(10).size(), "Single IP should not trigger multi-IP alert");

        AuditLogEntry entry2 = AuditLogEntry.withAuth("bob", "LOGIN", "Jenkins", "Login 2", "10.0.0.5", "form");
        detector.analyze(entry2, config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size(), "Should trigger MULTI_IP_LOGIN alert");
        assertEquals(AnomalyDetector.AnomalyType.MULTI_IP_LOGIN, alerts.get(0).type);
        assertEquals("bob", alerts.get(0).user);
        assertTrue(alerts.get(0).details.contains("2 distinct IP addresses"));
    }

    @Test
    void testSuspiciousAuthPatternDetection(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(5);
        config.setAnomalySuspiciousAuth(true);

        long now = System.currentTimeMillis();
        // Simulate failed login sequence
        for (int i = 0; i < 3; i++) {
            detector.analyze(new AuditLogEntry("charlie", "FAILED_LOGIN", "Jenkins", "Bad password", now + i * 1000), config);
        }

        // Simulate successful login following failed attempts
        AuditLogEntry successEntry = AuditLogEntry.withAuth("charlie", "LOGIN", "Jenkins", "Successful login", "192.168.1.5", "form");
        detector.analyze(successEntry, config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        boolean foundSuspicious = false;
        for (AnomalyDetector.AnomalyAlert alert : alerts) {
            if (alert.type == AnomalyDetector.AnomalyType.SUSPICIOUS_AUTH_PATTERN) {
                foundSuspicious = true;
                assertEquals("charlie", alert.user);
                assertTrue(alert.details.contains("successfully logged in immediately after"));
            }
        }
        assertTrue(foundSuspicious, "Should trigger SUSPICIOUS_AUTH_PATTERN alert");
    }

    @Test
    void testAdminPrivilegeChangeDetection(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyAdminPrivilegeChanges(true);

        AuditLogEntry entry = new AuditLogEntry("adminUser", "SECURITY_CONFIG_UPDATED", "GlobalMatrixAuthorizationStrategy", "Granted ADMINISTER to anonymous");
        detector.analyze(entry, config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size(), "Should trigger ADMIN_PRIVILEGE_CHANGE alert");
        assertEquals(AnomalyDetector.AnomalyType.ADMIN_PRIVILEGE_CHANGE, alerts.get(0).type);
        assertEquals("adminUser", alerts.get(0).user);
        assertEquals("CRITICAL", alerts.get(0).severity);
    }

    @Test
    void testUserLifecycleAnomalyDetection(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyUserLifecycle(true);
        config.setAnomalyUserLifecycleThreshold(1);
        config.setAnomalyUserLifecycleWindowMinutes(15);

        AuditLogEntry entry = new AuditLogEntry("adminUser", "USER_CREATED", "targetUser", "User account created: 'targetUser' by adminUser");
        detector.analyze(entry, config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size(), "Should trigger USER_LIFECYCLE_ANOMALY alert");
        assertEquals(AnomalyDetector.AnomalyType.USER_LIFECYCLE_ANOMALY, alerts.get(0).type);
        assertEquals("adminUser", alerts.get(0).user);
        assertEquals("HIGH", alerts.get(0).severity);
    }
}
