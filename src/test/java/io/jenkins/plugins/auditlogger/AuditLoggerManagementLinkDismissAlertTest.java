package io.jenkins.plugins.auditlogger;

import org.htmlunit.Page;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import jenkins.model.Jenkins;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditLoggerManagementLinkDismissAlertTest {

    @BeforeEach
    void setUp() {
        AuditLogStorage.getInstance().getAnomalyDetector().dismissAllAlerts();
    }

    @Test
    void testSingleAlertDismissalIsLoggedWithUserAndDetails(JenkinsRule j) throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER).everywhere().to("secadmin"));

        AnomalyDetector detector = AuditLogStorage.getInstance().getAnomalyDetector();
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                "badactor",
                "Multiple failed logins detected (5 attempts in 15 minutes).",
                "CRITICAL");
        detector.addAlert(alert);

        long startTs = System.currentTimeMillis();
        JenkinsRule.WebClient webClient = j.createWebClient().login("secadmin", "secadmin");
        Page page = webClient.goTo("manage/auditflow-logs/dismissAlert?alertId=" + alert.alertId, "application/json");

        assertEquals(200, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("\"success\":true"));

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().getAllEntries();
        AuditLogEntry dismissLog = null;
        for (int i = entries.size() - 1; i >= 0; i--) {
            AuditLogEntry e = entries.get(i);
            if ("ALERT_DISMISSED".equals(e.getAction()) && e.getTimestamp() >= startTs - 2000) {
                dismissLog = e;
                break;
            }
        }

        assertNotNull(dismissLog, "An ALERT_DISMISSED entry must be logged");
        assertEquals("secadmin", dismissLog.getUsername(), "Dismissal must record the user who dismissed the alert");
        assertEquals("ALERT_DISMISSED", dismissLog.getAction());
        assertEquals("BRUTE_FORCE_LOGIN (badactor)", dismissLog.getTarget());
        assertEquals("MEDIUM", dismissLog.getSeverity());

        String details = dismissLog.getDetails();
        assertTrue(details.contains(alert.alertId), "Details must include the alert ID");
        assertTrue(details.contains("BRUTE_FORCE_LOGIN"), "Details must include the anomaly type");
        assertTrue(details.contains("badactor"), "Details must include the subject user");
        assertTrue(details.contains("CRITICAL"), "Details must include the alert severity");
        assertTrue(details.contains("Multiple failed logins"), "Details must include the alert message");
    }

    @Test
    void testDismissAllIsLoggedWithItemizedListAndCount(JenkinsRule j) throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER).everywhere().to("chiefadmin"));

        AnomalyDetector detector = AuditLogStorage.getInstance().getAnomalyDetector();
        AnomalyDetector.AnomalyAlert alert1 = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                "userAlpha",
                "Brute force attempt on userAlpha",
                "CRITICAL");
        AnomalyDetector.AnomalyAlert alert2 = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.UNUSUAL_IP,
                "userBeta",
                "Unusual IP 192.168.1.100 for userBeta",
                "HIGH");
        detector.addAlert(alert1);
        detector.addAlert(alert2);

        long startTs = System.currentTimeMillis();
        JenkinsRule.WebClient webClient = j.createWebClient().login("chiefadmin", "chiefadmin");
        Page page = webClient.goTo("manage/auditflow-logs/dismissAlert?alertId=ALL", "application/json");

        assertEquals(200, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("\"success\":true"));

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().getAllEntries();
        AuditLogEntry dismissLog = null;
        for (int i = entries.size() - 1; i >= 0; i--) {
            AuditLogEntry e = entries.get(i);
            if ("ALERT_DISMISSED".equals(e.getAction()) && e.getTimestamp() >= startTs - 2000) {
                dismissLog = e;
                break;
            }
        }

        assertNotNull(dismissLog, "An ALERT_DISMISSED entry must be logged for dismiss all");
        assertEquals("chiefadmin", dismissLog.getUsername(), "Dismissal must record who dismissed all alerts");
        assertEquals("All Alerts (2 items)", dismissLog.getTarget());
        assertEquals("MEDIUM", dismissLog.getSeverity());

        String details = dismissLog.getDetails();
        assertTrue(details.contains("count: 2"), "Details must state the count of dismissed alerts");
        assertTrue(details.contains(alert1.alertId), "Details must include alert1 ID");
        assertTrue(details.contains("userAlpha"), "Details must include userAlpha");
        assertTrue(details.contains("BRUTE_FORCE_LOGIN"), "Details must include BRUTE_FORCE_LOGIN");
        assertTrue(details.contains(alert2.alertId), "Details must include alert2 ID");
        assertTrue(details.contains("userBeta"), "Details must include userBeta");
        assertTrue(details.contains("UNUSUAL_IP"), "Details must include UNUSUAL_IP");
    }

    @Test
    void testDismissAllWhenNoActiveAlerts(JenkinsRule j) throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER).everywhere().to("admin"));

        long startTs = System.currentTimeMillis();
        JenkinsRule.WebClient webClient = j.createWebClient().login("admin", "admin");
        Page page = webClient.goTo("manage/auditflow-logs/dismissAlert?alertId=ALL", "application/json");

        assertEquals(200, page.getWebResponse().getStatusCode());

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().getAllEntries();
        AuditLogEntry dismissLog = null;
        for (int i = entries.size() - 1; i >= 0; i--) {
            AuditLogEntry e = entries.get(i);
            if ("ALERT_DISMISSED".equals(e.getAction()) && e.getTimestamp() >= startTs - 2000) {
                dismissLog = e;
                break;
            }
        }

        assertNotNull(dismissLog);
        assertEquals("admin", dismissLog.getUsername());
        assertEquals("All Alerts (0 items)", dismissLog.getTarget());
        assertTrue(dismissLog.getDetails().contains("0 active alerts were present"));
    }
}
