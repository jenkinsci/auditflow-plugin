package io.jenkins.plugins.auditlogger;

import hudson.util.Secret;
import io.jenkins.plugins.auditlogger.AnomalyDetector.AnomalyAlert;
import io.jenkins.plugins.auditlogger.AnomalyDetector.AnomalyType;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class WebhookDispatcherTest {

    @Test
    void testBuildAuditLogPayloadFormatting(JenkinsRule j) {
        WebhookDispatcher dispatcher = new WebhookDispatcher();
        AuditLogEntry entry = new AuditLogEntry(
                "alice",
                "SCRIPT_CONSOLE_ACCESS",
                "RemotingDiagnostics",
                "println(System.getenv())",
                Instant.parse("2026-10-24T12:00:00Z").toEpochMilli()
        );
        entry.setSeverity("CRITICAL");

        String json = dispatcher.buildAuditLogPayload(entry, "https://jenkins.example.com/", "2026-10-24T12:00:00Z");

        assertNotNull(json);
        assertTrue(json.contains("\"type\":\"AUDIT_LOG\""));
        assertTrue(json.contains("\"severity\":\"CRITICAL\""));
        assertTrue(json.contains("\"user\":\"alice\""));
        assertTrue(json.contains("\"action\":\"SCRIPT_CONSOLE_ACCESS\""));
        assertTrue(json.contains("\"color\":\"#E01E5A\""));
        assertTrue(json.contains("🚨 [AuditFlow Alert] CRITICAL: SCRIPT_CONSOLE_ACCESS"));
        assertTrue(json.contains("https://jenkins.example.com/manage/auditflow-logs/"));
        assertTrue(json.contains("\"title\":\"Severity\",\"value\":\"CRITICAL\""));
        assertTrue(json.contains("\"title\":\"User\",\"value\":\"alice\""));
        assertTrue(json.contains("\"title\":\"Action\",\"value\":\"SCRIPT_CONSOLE_ACCESS\""));
    }

    @Test
    void testBuildAnomalyPayloadFormatting(JenkinsRule j) {
        WebhookDispatcher dispatcher = new WebhookDispatcher();
        AnomalyAlert alert = new AnomalyAlert(
                AnomalyType.BRUTE_FORCE_LOGIN,
                "attacker",
                "3 failed attempts from 10.0.0.1",
                "CRITICAL"
        );

        String json = dispatcher.buildAnomalyPayload(alert, "https://jenkins.example.com/", "2026-10-24T12:00:00Z");

        assertNotNull(json);
        assertTrue(json.contains("\"type\":\"BRUTE_FORCE_LOGIN\""));
        assertTrue(json.contains("\"severity\":\"CRITICAL\""));
        assertTrue(json.contains("\"user\":\"attacker\""));
        assertTrue(json.contains("Suspicious Login Attempts (Brute Force)"));
        assertTrue(json.contains("\"color\":\"#E01E5A\""));
        assertTrue(json.contains("`10.0.0.1`"), "IPv4 address should be wrapped in backticks for Slack");
    }

    @Test
    void testSeverityColorsAndEmojis() {
        assertEquals("#E01E5A", WebhookDispatcher.getSeverityColor("CRITICAL"));
        assertEquals("#ECB22E", WebhookDispatcher.getSeverityColor("HIGH"));
        assertEquals("#2EB886", WebhookDispatcher.getSeverityColor("MEDIUM"));
        assertEquals("#1D9BD1", WebhookDispatcher.getSeverityColor("LOW"));
        assertEquals("#1D9BD1", WebhookDispatcher.getSeverityColor("INFO"));
        assertEquals("#1D9BD1", WebhookDispatcher.getSeverityColor(null));

        assertEquals("🚨", WebhookDispatcher.getSeverityEmoji("CRITICAL"));
        assertEquals("⚠️", WebhookDispatcher.getSeverityEmoji("HIGH"));
        assertEquals("⚡", WebhookDispatcher.getSeverityEmoji("MEDIUM"));
        assertEquals("ℹ️", WebhookDispatcher.getSeverityEmoji("LOW"));
        assertEquals("ℹ️", WebhookDispatcher.getSeverityEmoji(null));
    }

    @Test
    void testSlackDetailsIpv4Formatting() {
        String details = "Connection from 192.168.1.100 and 10.0.0.1 failed";
        String formatted = WebhookDispatcher.formatDetailsForSlack(details);
        assertEquals("Connection from `192.168.1.100` and `10.0.0.1` failed", formatted);
    }

    @Test
    void testDispatchAuditLogWhenDisabled(JenkinsRule j) {
        WebhookDispatcher dispatcher = new WebhookDispatcher();
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setEnableWebhookAlerts(false);

        AuditLogEntry entry = new AuditLogEntry("user", "TEST_ACTION", "target", "msg");
        entry.setSeverity("CRITICAL");

        // Should return cleanly without error
        assertDoesNotThrow(() -> dispatcher.dispatchAuditLog(entry, config));
        assertDoesNotThrow(() -> dispatcher.dispatchAuditLog(null, config));
        assertDoesNotThrow(() -> dispatcher.dispatchAuditLog(entry, null));
    }

    @Test
    void testDispatchAnomalyWhenDisabled(JenkinsRule j) {
        WebhookDispatcher dispatcher = new WebhookDispatcher();
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setEnableWebhookAlerts(false);

        AnomalyAlert alert = new AnomalyAlert(AnomalyType.ADMIN_PRIVILEGE_CHANGE, "admin", "details", "HIGH");

        assertDoesNotThrow(() -> dispatcher.dispatchAnomaly(alert, config));
        assertDoesNotThrow(() -> dispatcher.dispatchAnomaly(null, config));
        assertDoesNotThrow(() -> dispatcher.dispatchAnomaly(alert, null));
    }
}
