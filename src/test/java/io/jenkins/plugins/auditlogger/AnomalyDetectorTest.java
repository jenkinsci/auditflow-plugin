package io.jenkins.plugins.auditlogger;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class AnomalyDetectorTest {

    private final List<jakarta.mail.internet.MimeMessage> sentEmails = new ArrayList<>();

    /** Captures webhook calls: each entry is [url, json] */
    private final List<String[]> sentWebhooks = new ArrayList<>();

    private AnomalyDetector detector;

    @BeforeEach
    void setup() {
        sentEmails.clear();
        sentWebhooks.clear();
        detector = new AnomalyDetector() {
            @Override
            protected void sendEmail(jakarta.mail.internet.MimeMessage msg) throws Exception {
                sentEmails.add(msg);
            }

            @Override
            protected void sendWebhook(String url, String json) throws Exception {
                sentWebhooks.add(new String[]{url, json});
            }
        };
    }

    // ── Basic detection ──────────────────────────────────────────────

    @Test
    void testBruteForceLoginAnomalyIsDetected(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(3);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableEmailAlerts(false);

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("testuser", "FAILED_LOGIN", "jenkins", "", now), config);
        assertEquals(0, detector.getAlerts(10).size(), "Should not trigger yet");

        detector.analyze(new AuditLogEntry("testuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);
        assertEquals(0, detector.getAlerts(10).size(), "Should not trigger yet");

        detector.analyze(new AuditLogEntry("testuser", "FAILED_LOGIN", "jenkins", "", now + 2000), config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size(), "Should trigger alert");
        assertEquals(AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN, alerts.get(0).type);
        assertEquals("testuser", alerts.get(0).user);
    }

    // ── Email tests ──────────────────────────────────────────────────

    @Test
    void testEmailAlertsConfiguration(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableEmailAlerts(true);
        config.setAlertEmailAddresses("test@example.com, ");

        hudson.tasks.Mailer.descriptor().setAdminAddress(null);

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("emailuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("emailuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, detector.getAlerts(10).size());
        assertEquals(1, sentEmails.size(), "Email should have been sent");
    }

    @Test
    void testNullConfigAndEmptyEmailAlerts(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(1);
        config.setAnomalyFailedLoginsWindowMinutes(1);

        // config == null path
        detector.analyze(new AuditLogEntry("nullconfuser", "FAILED_LOGIN", "jenkins", "", System.currentTimeMillis()), null);

        // empty email
        config.setEnableEmailAlerts(true);
        config.setAlertEmailAddresses("   ");
        detector.analyze(new AuditLogEntry("emptyemailuser", "FAILED_LOGIN", "jenkins", "", System.currentTimeMillis()), config);

        config.setAlertEmailAddresses("test@example.com");
        detector.analyze(new AuditLogEntry("nojenkinsuser", "FAILED_LOGIN", "jenkins", "", System.currentTimeMillis()), config);
    }

    // ── Webhook tests ────────────────────────────────────────────────

    @Test
    void testWebhookSentOnAnomalyAlert(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl("https://hooks.example.com/alert");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("whuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("whuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, detector.getAlerts(10).size(), "Alert should be recorded");
        assertEquals(1, sentWebhooks.size(), "Webhook should have been called");
        assertEquals("https://hooks.example.com/alert", sentWebhooks.get(0)[0]);

        String json = sentWebhooks.get(0)[1];
        assertTrue(json.contains("\"type\":\"BRUTE_FORCE_LOGIN\""), "JSON should contain type");
        assertTrue(json.contains("\"severity\":\"CRITICAL\""), "JSON should contain severity");
        assertTrue(json.contains("\"user\":\"whuser\""), "JSON should contain user");
    }

    @Test
    void testWebhookSkippedWhenDisabled(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(false);
        config.setWebhookUrl("https://hooks.example.com/alert");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("nowhuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("nowhuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, detector.getAlerts(10).size(), "Alert should still be recorded");
        assertEquals(0, sentWebhooks.size(), "Webhook should NOT be called when disabled");
    }

    @Test
    void testWebhookSkippedWhenUrlEmpty(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl("   "); // blank

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("emptyurl", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("emptyurl", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, detector.getAlerts(10).size());
        assertEquals(0, sentWebhooks.size(), "Webhook should NOT be called with blank URL");
    }

    @Test
    void testWebhookSkippedWhenUrlNull(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl(null);

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("nullurl", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("nullurl", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, detector.getAlerts(10).size());
        assertEquals(0, sentWebhooks.size(), "Webhook should NOT be called with null URL");
    }

    @Test
    void testWebhookExceptionIsCaught(JenkinsRule j) {
        // Override with a throwing sendWebhook
        detector = new AnomalyDetector() {
            @Override
            protected void sendEmail(jakarta.mail.internet.MimeMessage msg) throws Exception {
                
            }

            @Override
            protected void sendWebhook(String url, String json) throws Exception {
                throw new RuntimeException("Simulated webhook failure");
            }
        };

        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl("https://hooks.example.com/fail");

        long now = System.currentTimeMillis();
        // Should NOT throw 
        detector.analyze(new AuditLogEntry("failwh", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("failwh", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, detector.getAlerts(10).size(), "Alert should still be recorded despite webhook failure");
    }

    @Test
    void testBothEmailAndWebhookFire(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableEmailAlerts(true);
        config.setAlertEmailAddresses("both@example.com");
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl("https://hooks.example.com/both");

        hudson.tasks.Mailer.descriptor().setAdminAddress("admin@jenkins.local");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("bothuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("bothuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, detector.getAlerts(10).size());
        assertEquals(1, sentEmails.size(), "Email should fire");
        assertEquals(1, sentWebhooks.size(), "Webhook should fire");
    }

    // ── Coverage: escapeJson null branch (line 313) ──────────────────

    @Test
    void testEscapeJsonWithNullInput(JenkinsRule j) throws Exception {
        // Use reflection to test the private escapeJson method with null
        java.lang.reflect.Method escapeJson = AnomalyDetector.class.getDeclaredMethod("escapeJson", String.class);
        escapeJson.setAccessible(true);
        String result = (String) escapeJson.invoke(null, (Object) null);
        assertEquals("", result, "escapeJson(null) should return empty string");
    }

    // ── Coverage: sendWebhookNotification internal branches (lines 260, 266, 268) ──

    @Test
    void testWebhookNotificationCoversJenkinsUrlBranches(JenkinsRule j) {
        
        final List<String[]> captured = new ArrayList<>();
        AnomalyDetector realPathDetector = new AnomalyDetector() {
            @Override
            protected void sendEmail(jakarta.mail.internet.MimeMessage msg) throws Exception {
               
            }

            @Override
            protected void sendWebhook(String url, String json) throws Exception {
                captured.add(new String[]{url, json});
            }
        };

        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl("https://hooks.example.com/coverage");

        long now = System.currentTimeMillis();
        realPathDetector.analyze(new AuditLogEntry("covuser", "FAILED_LOGIN", "jenkins", "", now), config);
        realPathDetector.analyze(new AuditLogEntry("covuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, captured.size(), "sendWebhook should have been called");
        String json = captured.get(0)[1];
        assertTrue(json.contains("\"jenkinsUrl\""), "JSON should contain jenkinsUrl field");
    }

   

    @Test
    void testRealSendWebhookMethodIsCovered(JenkinsRule j) throws Exception {
        // Call the real sendWebhook directly with a URL that will fail connection
        // The async nature means it won't throw — the exceptionally handler will catch it.
        AnomalyDetector realDetector = new AnomalyDetector();
        // Use a non-routable address so it fails fast but still exercises the code
        realDetector.sendWebhook("http://192.0.2.1:1/test", "{\"test\":true}");
        assertTrue(true, "sendWebhook should not throw (async)");

        // Test 200 OK and 400 Bad Request branches using local HttpServer
        CountDownLatch latch200 = new CountDownLatch(1);
        CountDownLatch latch400 = new CountDownLatch(1);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/webhook-200", exchange -> {
            byte[] resp = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
            latch200.countDown();
        });
        server.createContext("/webhook-400", exchange -> {
            byte[] resp = "no_text".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(400, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
            latch400.countDown();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            realDetector.sendWebhook("http://127.0.0.1:" + port + "/webhook-200", "{\"text\":\"alert\"}");
            assertTrue(latch200.await(5, TimeUnit.SECONDS), "200 endpoint should be hit");

            realDetector.sendWebhook("http://127.0.0.1:" + port + "/webhook-400", "{\"type\":\"test\"}");
            assertTrue(latch400.await(5, TimeUnit.SECONDS), "400 endpoint should be hit");
        } finally {
            server.stop(0);
        }
    }

    // ── Enhanced email and webhook format tests ──────────────────────

    @Test
    void testEnhancedEmailFormatContainsTimestamp(JenkinsRule j) throws Exception {
        hudson.tasks.Mailer.descriptor().setAdminAddress("admin@jenkins.local");
        
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableEmailAlerts(true);
        config.setAlertEmailAddresses("alert@example.com");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("emailuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("emailuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, sentEmails.size(), "Email should be sent");
        jakarta.mail.internet.MimeMessage email = sentEmails.get(0);
        String content = (String) email.getContent();
        
        assertTrue(content.contains("Anomaly Detected in Jenkins AuditFlow"), 
                "Email should have title");
        assertTrue(content.contains("Timestamp:"), "Email should include timestamp");
        assertTrue(content.contains("Details:"), "Email should have details section");
        assertTrue(content.contains("Review the AuditFlow logs"), 
                "Email should have investigation prompt");
    }

    @Test
    void testEnhancedEmailFormatIncludesReadableAnomalyType(JenkinsRule j) throws Exception {
        hudson.tasks.Mailer.descriptor().setAdminAddress("admin@jenkins.local");
        
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableEmailAlerts(true);
        config.setAlertEmailAddresses("alert@example.com");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("emailuser2", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("emailuser2", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, sentEmails.size(), "Email should be sent");
        jakarta.mail.internet.MimeMessage email = sentEmails.get(0);
        String content = (String) email.getContent();
        
        assertTrue(content.contains("Suspicious Login Attempts (Brute Force)"), 
                "Email should contain readable anomaly type");
    }

    @Test
    void testEnhancedWebhookPayloadContainsAllRequiredFields(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl("https://hooks.example.com/enhanced");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("webhookuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("webhookuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, sentWebhooks.size(), "Webhook should be sent");
        String json = sentWebhooks.get(0)[1];
        
        assertTrue(json.contains("\"text\":\""), "Webhook should contain text property for Slack/Teams compatibility");
        assertTrue(json.contains("[AuditFlow Alert]"), "Webhook text should contain alert prefix");
        assertTrue(json.contains("Suspicious Login Attempts (Brute Force)"), "Webhook text should contain readable type");
        assertTrue(json.contains("\"type\":\"BRUTE_FORCE_LOGIN\""), "Webhook should contain type");
        assertTrue(json.contains("\"severity\":\"CRITICAL\""), "Webhook should contain severity");
        assertTrue(json.contains("\"user\":\"webhookuser\""), "Webhook should contain user");
        assertTrue(json.contains("\"details\":\""), "Webhook should contain details");
        assertTrue(json.contains("\"timestamp\":\""), "Webhook should contain ISO timestamp");
        assertTrue(json.contains("\"timestampMs\":"), "Webhook should contain millisecond timestamp");
        assertTrue(json.contains("\"alertId\":\""), "Webhook should contain alertId");
        assertTrue(json.contains("\"source\":\"Jenkins Audit Logger\""), 
                "Webhook should contain source");
        assertTrue(json.contains("\"version\":\"1.0\""), "Webhook should contain version");
    }

    @Test
    void testBuildWebhookPayloadSlackAndTeamsCompatibility(JenkinsRule j) {
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                "admin",
                "Multiple failed logins (5 attempts)",
                "CRITICAL"
        );
        String jenkinsUrl = "https://ci.example.com/";
        String isoTimestamp = "2026-10-14T17:00:00.000Z";

        AnomalyDetector defaultDetector = new AnomalyDetector();
        String json = defaultDetector.buildWebhookPayload(alert, jenkinsUrl, isoTimestamp);

        // Verify JSON envelope
        assertTrue(json.startsWith("{") && json.endsWith("}"), "Payload must be valid JSON object");

        // Verify text field for Slack / Teams
        assertTrue(json.contains("\"text\":\"[AuditFlow Alert] CRITICAL: Suspicious Login Attempts (Brute Force) - User: 'admin' | Multiple failed logins (5 attempts) (Jenkins: https://ci.example.com/)\""),
                "Text field should be formatted properly for Slack/Teams");

        // Verify existing payload fields are intact
        assertTrue(json.contains("\"type\":\"BRUTE_FORCE_LOGIN\""));
        assertTrue(json.contains("\"severity\":\"CRITICAL\""));
        assertTrue(json.contains("\"user\":\"admin\""));
        assertTrue(json.contains("\"details\":\"Multiple failed logins (5 attempts)\""));
        assertTrue(json.contains("\"timestamp\":\"2026-10-14T17:00:00.000Z\""));
        assertTrue(json.contains("\"timestampMs\":" + alert.timestamp));
        assertTrue(json.contains("\"jenkinsUrl\":\"https://ci.example.com/\""));
        assertTrue(json.contains("\"alertId\":\"" + alert.alertId + "\""));
        assertTrue(json.contains("\"source\":\"Jenkins Audit Logger\""));
        assertTrue(json.contains("\"version\":\"1.0\""));
    }

    @Test
    void testBuildWebhookPayloadWithEmptyDetailsAndNullJenkinsUrl() {
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.UNUSUAL_IP,
                "alice",
                "",
                "HIGH"
        );
        AnomalyDetector defaultDetector = new AnomalyDetector();
        String json = defaultDetector.buildWebhookPayload(alert, null, "2026-10-14T17:00:00.000Z");

        assertTrue(json.contains("\"text\":\"[AuditFlow Alert] HIGH: Unusual IP Address Activity - User: 'alice'\""),
                "Text field should omit empty details and null jenkinsUrl cleanly");
    }

    @Test
    void testWebhookPayloadIsoTimestampIsValid(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl("https://hooks.example.com/timestamp");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("timestampuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("timestampuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, sentWebhooks.size(), "Webhook should be sent");
        String json = sentWebhooks.get(0)[1];
        
        // Extract ISO timestamp from JSON
        int startIdx = json.indexOf("\"timestamp\":\"") + 13;
        int endIdx = json.indexOf("\"", startIdx);
        String isoTimestamp = json.substring(startIdx, endIdx);
        
        // ISO 8601 format: YYYY-MM-DDTHH:MM:SS.SSSZ
        assertTrue(isoTimestamp.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z"),
                "Webhook timestamp should be ISO 8601 format");
    }

    @Test
    void testWebhookPayloadAlertIdIsUnique(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl("https://hooks.example.com/alertid");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("alertiduser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("alertiduser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        assertEquals(1, sentWebhooks.size(), "Webhook should be sent");
        String json = sentWebhooks.get(0)[1];
        
        assertTrue(json.contains("\"alertId\":\"auditflow-BRUTE_FORCE_LOGIN-alertiduser-"), 
                "Alert ID should follow pattern: auditflow-{type}-{user}-{timestamp}");
    }

    @Test
    void testValidationFailsOnInvalidEmail(JenkinsRule j) throws Exception {
        hudson.tasks.Mailer.descriptor().setAdminAddress("admin@jenkins.local");
        
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableEmailAlerts(true);
        config.setAlertEmailAddresses("invalid-email-format");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("validationuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("validationuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        // Email should NOT be sent because validation failed
        assertEquals(0, sentEmails.size(), "Email should not be sent for invalid email address");
    }

    @Test
    void testValidationFailsOnInvalidWebhookUrl(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);
        config.setEnableWebhookAlerts(true);
        config.setWebhookUrl("not-a-valid-url");

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("validationuser2", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("validationuser2", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        // Webhook should NOT be sent because validation failed
        assertEquals(0, sentWebhooks.size(), "Webhook should not be sent for invalid URL");
    }

    @Test
    void testDismissedAlertIsExcludedFromOpenAlerts(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("dismissuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("dismissuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size(), "Alert should be present before dismissal");

        String alertId = alerts.get(0).alertId;
        assertTrue(detector.dismissAlert(alertId), "Dismiss should return true for existing alert");
        assertEquals(0, detector.getAlerts(10).size(), "Dismissed alert should be excluded from open alerts");
    }

    @Test
    void testDismissAlertReturnsFalseForUnknownId(JenkinsRule j) {
        assertEquals(false, detector.dismissAlert("nonexistent-id"), "Dismiss should return false for unknown alert id");
    }

    @Test
    void testDismissAllAlerts(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("user1", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("user1", "FAILED_LOGIN", "jenkins", "", now + 1000), config);
        detector.analyze(new AuditLogEntry("user2", "FAILED_LOGIN", "jenkins", "", now + 2000), config);
        detector.analyze(new AuditLogEntry("user2", "FAILED_LOGIN", "jenkins", "", now + 3000), config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(2, alerts.size(), "Should have 2 open alerts before dismissAll");

        int dismissed = detector.dismissAllAlerts();
        assertEquals(2, dismissed, "Should dismiss both alerts");
        assertEquals(0, detector.getAlerts(10).size(), "All alerts should be dismissed");
    }

    @Test
    void testDismissAndGetAlert(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("testuser", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("testuser", "FAILED_LOGIN", "jenkins", "", now + 1000), config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(1, alerts.size());

        String alertId = alerts.get(0).alertId;
        AnomalyDetector.AnomalyAlert dismissed = detector.dismissAndGetAlert(alertId);
        assertNotNull(dismissed, "dismissAndGetAlert should return dismissed alert");
        assertEquals(alertId, dismissed.alertId);
        assertEquals("testuser", dismissed.user);
        assertTrue(dismissed.isDismissed());

        // Subsequent call returns null
        assertNull(detector.dismissAndGetAlert(alertId), "Second dismissAndGetAlert should return null");
        assertNull(detector.dismissAndGetAlert("nonexistent"), "dismissAndGetAlert with unknown id should return null");
    }

    @Test
    void testDismissAllAndGetAlerts(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setAnomalyFailedLogins(true);
        config.setAnomalyFailedLoginsThreshold(2);
        config.setAnomalyFailedLoginsWindowMinutes(1);

        long now = System.currentTimeMillis();
        detector.analyze(new AuditLogEntry("user1", "FAILED_LOGIN", "jenkins", "", now), config);
        detector.analyze(new AuditLogEntry("user1", "FAILED_LOGIN", "jenkins", "", now + 1000), config);
        detector.analyze(new AuditLogEntry("user2", "FAILED_LOGIN", "jenkins", "", now + 2000), config);
        detector.analyze(new AuditLogEntry("user2", "FAILED_LOGIN", "jenkins", "", now + 3000), config);

        List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
        assertEquals(2, alerts.size());

        List<AnomalyDetector.AnomalyAlert> dismissed = detector.dismissAllAndGetAlerts();
        assertEquals(2, dismissed.size());
        assertEquals(0, detector.getAlerts(10).size());

        // Calling again returns empty list
        List<AnomalyDetector.AnomalyAlert> dismissedSecond = detector.dismissAllAndGetAlerts();
        assertTrue(dismissedSecond.isEmpty());
    }

    @Test
    void testNoAnomaliesReturnedWhenAllRulesDisabled(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setEnableAnomalyDetection(true);
        // disable all rules
        config.setAnomalyFailedLogins(false);
        config.setAnomalyUnusualIp(false);
        config.setAnomalyMultiIpLogin(false);
        config.setAnomalySuspiciousAuth(false);
        config.setAnomalyAdminPrivilegeChanges(false);
        config.setAnomalyUserLifecycle(false);
        config.setAnomalyGlobalConfigChanges(false);
        config.setAnomalyJobConfigChanges(false);
        config.setAnomalyOffHoursAdmin(false);
        config.setAnomalyCredentialChanges(false);
        config.setAnomalySecurityConfigChanges(false);
        config.setAnomalyPluginChanges(false);
        config.setAnomalyBuildFailures(false);

        assertEquals(false, config.isAnyAnomalyRuleEnabled(), "Should report no anomaly rule enabled");

        detector.addAlert(new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN, "testuser", "details", "CRITICAL"));

        assertEquals(0, detector.getAlerts(10, config).size(), "Alerts list should be empty when no rules enabled");

        AuditFlowPageDecorator decorator = new AuditFlowPageDecorator();
        // Even if active alerts exist in memory, isBannerVisible must return false
        assertEquals(false, decorator.isBannerVisible(), "Banner must not be visible when no rules enabled");
    }

    @Test
    void testDismissAlertsForDisabledRulesPrunesStaleAlerts(JenkinsRule j) {
        AuditLoggerConfiguration config = new AuditLoggerConfiguration();
        config.setEnableAnomalyDetection(true);
        config.setAnomalyFailedLogins(true);
        config.setAnomalyUnusualIp(false);

        detector.addAlert(new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN, "user1", "failed login", "CRITICAL"));
        detector.addAlert(new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.UNUSUAL_IP, "user2", "unusual ip", "MEDIUM"));

        // Before pruning: BRUTE_FORCE_LOGIN is enabled, UNUSUAL_IP is disabled
        List<AnomalyDetector.AnomalyAlert> alertsBefore = detector.getAlerts(10, config);
        assertEquals(1, alertsBefore.size());
        assertEquals(AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN, alertsBefore.get(0).type);

        // Prune alerts for disabled rules
        detector.dismissAlertsForDisabledRules(config);

        // Now disable all rules
        config.setAnomalyFailedLogins(false);
        detector.dismissAlertsForDisabledRules(config);

        assertEquals(0, detector.getAlerts(10, config).size(), "All alerts should be pruned when all rules disabled");
    }
}