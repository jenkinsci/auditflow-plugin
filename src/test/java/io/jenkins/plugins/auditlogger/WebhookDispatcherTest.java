package io.jenkins.plugins.auditlogger;

import hudson.util.Secret;
import io.jenkins.plugins.auditlogger.AnomalyDetector.AnomalyAlert;
import io.jenkins.plugins.auditlogger.AnomalyDetector.AnomalyType;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
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
    void testIsTeamsWebhookUrl() {
        assertTrue(WebhookDispatcher.isTeamsWebhookUrl(
                "https://default1234.56.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke?sig=x"));
        assertTrue(WebhookDispatcher.isTeamsWebhookUrl("https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke"));
        assertTrue(WebhookDispatcher.isTeamsWebhookUrl("https://prod-01.usgovtexas.logic.azure.us/workflows/abc"));
        assertTrue(WebhookDispatcher.isTeamsWebhookUrl("https://contoso.webhook.office.com/webhookb2/abc"));
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl("https://hooks.slack.com/services/T00/B00/XXX"));
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl("https://example.com/office.com/hook"));
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl("not a url"));
        assertFalse(WebhookDispatcher.isTeamsWebhookUrl(null));
    }

    @Test
    void testBuildTeamsAuditLogPayloadIsAdaptiveCard() {
        AuditLogEntry entry = new AuditLogEntry("alice", "SCRIPT_CONSOLE_ACCESS", "RemotingDiagnostics",
                "println(\"x\")", Instant.parse("2026-10-24T12:00:00Z").toEpochMilli());
        entry.setSeverity("CRITICAL");

        String json = WebhookDispatcher.buildTeamsAuditLogPayload(entry, "https://jenkins.example.com/", "2026-10-24T12:00:00Z");

        JSONObject root = JSONObject.fromObject(json);
        assertEquals("message", root.getString("type"));
        JSONObject attachment = root.getJSONArray("attachments").getJSONObject(0);
        assertEquals("application/vnd.microsoft.card.adaptive", attachment.getString("contentType"));
        JSONObject card = attachment.getJSONObject("content");
        assertEquals("AdaptiveCard", card.getString("type"));
        assertEquals("1.4", card.getString("version"));
        JSONArray body = card.getJSONArray("body");
        assertEquals("Attention", body.getJSONObject(0).getString("color"));
        assertTrue(body.getJSONObject(0).getString("text").contains("CRITICAL: SCRIPT_CONSOLE_ACCESS"));
        assertTrue(body.getJSONObject(1).toString().contains("\"value\":\"alice\""));
        assertEquals("println(\"x\")", body.getJSONObject(2).getString("text"));
        assertEquals("https://jenkins.example.com/manage/auditflow-logs/",
                card.getJSONArray("actions").getJSONObject(0).getString("url"));
        assertFalse(json.contains("\"color\":\"#"), "Slack attachment fields must not leak into Teams payload");
    }

    @Test
    void testBuildTeamsAnomalyPayloadIsAdaptiveCard() {
        AnomalyAlert alert = new AnomalyAlert(AnomalyType.BRUTE_FORCE_LOGIN, "attacker", "3 failed attempts from 10.0.0.1", "HIGH");

        String json = WebhookDispatcher.buildTeamsAnomalyPayload(alert, "", "2026-10-24T12:00:00Z");

        JSONObject card = JSONObject.fromObject(json).getJSONArray("attachments").getJSONObject(0).getJSONObject("content");
        assertEquals("1.4", card.getString("version"));
        assertEquals("Warning", card.getJSONArray("body").getJSONObject(0).getString("color"));
        assertTrue(json.contains("Suspicious Login Attempts (Brute Force)"));
        assertTrue(json.contains("3 failed attempts from 10.0.0.1"));
        assertFalse(card.has("actions"), "No link action without a Jenkins root URL");
    }

    @Test
    void testResponseSnippetIsCapped() {
        assertEquals("", WebhookDispatcher.responseSnippet(null, ": "));
        assertEquals("", WebhookDispatcher.responseSnippet("  ", ": "));
        assertEquals(": short", WebhookDispatcher.responseSnippet(" short ", ": "));
        String capped = WebhookDispatcher.responseSnippet("x".repeat(1000), ": ");
        assertEquals(2 + 250 + 3, capped.length());
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
}
