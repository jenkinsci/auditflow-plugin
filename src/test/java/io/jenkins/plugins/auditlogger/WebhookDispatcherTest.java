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

    @Test
    void testRfc8259JsonEscaping() {
        assertEquals("", WebhookDispatcher.escapeJson(null));
        assertEquals("simple text", WebhookDispatcher.escapeJson("simple text"));
        assertEquals("quote: \\\"hello\\\"", WebhookDispatcher.escapeJson("quote: \"hello\""));
        assertEquals("line1\\nline2", WebhookDispatcher.escapeJson("line1\r\nline2"));
        assertEquals("indented:\\tcode", WebhookDispatcher.escapeJson("indented:\tcode"));
        assertEquals("backspace:\\b formfeed:\\f", WebhookDispatcher.escapeJson("backspace:\b formfeed:\f"));
        assertEquals("control:\\u0007", WebhookDispatcher.escapeJson("control:\u0007"));
    }

    @Test
    void testScriptConsoleDerivesCriticalSeverity() {
        AuditLogEntry scriptEntry = new AuditLogEntry("admin", "SCRIPT_CONSOLE_ACCESS", "Remoting", "println 'test'");
        assertEquals("CRITICAL", scriptEntry.getSeverity());

        AuditLogEntry execEntry = new AuditLogEntry("admin", "SCRIPT_EXECUTION", "Remoting", "println 'test'");
        assertEquals("CRITICAL", execEntry.getSeverity());
    }

    @Test
    void testMaskWebhookUrl() {
        assertEquals("", WebhookDispatcher.maskWebhookUrl(null));
        assertEquals("", WebhookDispatcher.maskWebhookUrl("   "));
        assertEquals("https://hooks.slack.com/services/***",
                WebhookDispatcher.maskWebhookUrl("https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"));
        assertEquals("https://discord.com/api/***",
                WebhookDispatcher.maskWebhookUrl("https://discord.com/api/webhooks/123456/abcdef-secret-token"));
        assertEquals("https://example.com/webhook/***",
                WebhookDispatcher.maskWebhookUrl("https://example.com/webhook?key=sensitive_secret_token"));
    }

    @Test
    void testExecutorReinitializationAfterShutdown() {
        WebhookDispatcher dispatcher = new WebhookDispatcher();
        assertNotNull(dispatcher.getExecutor());
        assertFalse(dispatcher.getExecutor().isShutdown());

        dispatcher.shutdown();
        assertTrue(dispatcher.getExecutor().isShutdown() || !dispatcher.getExecutor().isTerminated());

        // Calling getExecutor() must self-heal and return a new active executor
        var activeExecutor = dispatcher.getExecutor();
        assertNotNull(activeExecutor);
        assertFalse(activeExecutor.isShutdown());

        dispatcher.shutdown();
    }

    @Test
    void testIsTeamsWebhookUrlDetection() {
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl(null));
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl(""));
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl("   "));
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl("https://hooks.slack.com/services/T00/B00/SECRET"));
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl("https://discord.com/api/webhooks/123/xyz"));
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl("https://example.com/custom/webhook"));

        assertTrue(WebhookDispatcher.isTeamsWebhookUrl("https://prod-12.eastus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-10-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=xyz"));
        assertTrue(WebhookDispatcher.isTeamsWebhookUrl("https://myenv.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke"));
        assertTrue(WebhookDispatcher.isTeamsWebhookUrl("https://outlook.office.com/webhook/abc-123"));
        assertTrue(WebhookDispatcher.isTeamsWebhookUrl("https://myorg.webhook.office.com/webhookb2/uuid@tenant/IncomingWebhook/xxx"));
        assertTrue(WebhookDispatcher.isTeamsWebhookUrl("https://prod-05.powerautomate.com/workflows/test"));
        assertTrue(WebhookDispatcher.isTeamsWebhookUrl("https://flow.microsoft.com/triggers/manual"));
    }

    @Test
    void testBuildTeamsAuditLogPayload(JenkinsRule j) {
        WebhookDispatcher dispatcher = new WebhookDispatcher();
        AuditLogEntry entry = new AuditLogEntry(
                "bob",
                "USER_CONFIG_CHANGED",
                "users/bob",
                "Updated public SSH keys",
                Instant.parse("2026-10-29T18:00:00Z").toEpochMilli()
        );
        entry.setSeverity("HIGH");

        String json = dispatcher.buildTeamsAuditLogPayload(entry, "https://jenkins.example.com/", "2026-10-29T18:00:00Z");

        assertNotNull(json);
        assertTrue(json.contains("\"type\":\"message\""));
        assertTrue(json.contains("\"contentType\":\"application/vnd.microsoft.card.adaptive\""));
        assertTrue(json.contains("\"type\":\"AdaptiveCard\""));
        assertTrue(json.contains("\"version\":\"1.4\""));
        assertTrue(json.contains("⚠️ [AuditFlow Alert] HIGH: USER_CONFIG_CHANGED"));
        assertTrue(json.contains("\"title\":\"User\",\"value\":\"bob\""));
        assertTrue(json.contains("\"title\":\"Action\",\"value\":\"USER_CONFIG_CHANGED\""));
        assertTrue(json.contains("\"title\":\"Severity\",\"value\":\"HIGH\""));
        assertTrue(json.contains("\"title\":\"Target\",\"value\":\"users/bob\""));
        assertTrue(json.contains("\"title\":\"Details\",\"value\":\"Updated public SSH keys\""));
        assertTrue(json.contains("\"title\":\"Timestamp\",\"value\":\"2026-10-29T18:00:00Z\""));
        assertTrue(json.contains("\"type\":\"Action.OpenUrl\""));
        assertTrue(json.contains("https://jenkins.example.com/manage/auditflow-logs/"));
    }

    @Test
    void testBuildTeamsAnomalyPayload(JenkinsRule j) {
        WebhookDispatcher dispatcher = new WebhookDispatcher();
        AnomalyAlert alert = new AnomalyAlert(
                AnomalyType.CREDENTIAL_EXPOSURE,
                "attacker",
                "Potential credential leak detected",
                "CRITICAL"
        );

        String json = dispatcher.buildTeamsAnomalyPayload(alert, "https://jenkins.example.com/", "2026-10-29T18:00:00Z");

        assertNotNull(json);
        assertTrue(json.contains("\"type\":\"message\""));
        assertTrue(json.contains("\"contentType\":\"application/vnd.microsoft.card.adaptive\""));
        assertTrue(json.contains("\"type\":\"AdaptiveCard\""));
        assertTrue(json.contains("🚨 [AuditFlow Alert] CRITICAL: Potential Credential Exposure"));
        assertTrue(json.contains("\"title\":\"Anomaly Type\",\"value\":\"Potential Credential Exposure\""));
        assertTrue(json.contains("\"title\":\"User\",\"value\":\"attacker\""));
        assertTrue(json.contains("\"title\":\"Severity\",\"value\":\"CRITICAL\""));
        assertTrue(json.contains("\"title\":\"Details\",\"value\":\"Potential credential leak detected\""));
        assertTrue(json.contains("\"type\":\"Action.OpenUrl\""));
    }

    @Test
    void testBuildTeamsTestPayload() {
        String json = WebhookEndpoint.buildTeamsTestPayload();
        assertNotNull(json);
        assertTrue(json.contains("\"type\":\"message\""));
        assertTrue(json.contains("\"contentType\":\"application/vnd.microsoft.card.adaptive\""));
        assertTrue(json.contains("\"type\":\"AdaptiveCard\""));
        assertTrue(json.contains("Connected"));
        assertTrue(json.contains("Jenkins AuditFlow"));
    }
}
