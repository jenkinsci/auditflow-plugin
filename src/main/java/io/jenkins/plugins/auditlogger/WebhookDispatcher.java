package io.jenkins.plugins.auditlogger;

import hudson.util.FormValidation;
import io.jenkins.plugins.auditlogger.AnomalyDetector.AnomalyAlert;
import io.jenkins.plugins.auditlogger.AnomalyDetector.AnomalyType;
import jenkins.model.Jenkins;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Asynchronous dispatcher for sending security alerts and audit logs to external
 * webhook endpoints (Slack, Microsoft Teams, generic receivers).
 * Provides worker daemon threads, retry logic with exponential backoff on HTTP 429/5xx,
 * and unified payload formatting.
 */
public class WebhookDispatcher {
    private static final Logger LOGGER = Logger.getLogger(WebhookDispatcher.class.getName());
    private static final int MAX_RETRIES = 3;
    private static final WebhookDispatcher INSTANCE = new WebhookDispatcher();

    private final ScheduledExecutorService executor;
    private HttpClient httpClient;

    public static WebhookDispatcher getInstance() {
        return INSTANCE;
    }

    public WebhookDispatcher() {
        this.executor = Executors.newScheduledThreadPool(2, new ThreadFactory() {
            private final AtomicInteger count = new AtomicInteger(1);
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "AuditFlow-Webhook-Worker-" + count.getAndIncrement());
                t.setDaemon(true);
                return t;
            }
        });
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /** Package-private setter for unit tests to inject custom HttpClient */
    void setHttpClient(HttpClient client) {
        this.httpClient = client;
    }

    private HttpClient getHttpClient() {
        if (httpClient == null) {
            httpClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
        }
        return httpClient;
    }

    /**
     * Dispatches an anomaly alert to all active endpoints configured in AuditLoggerConfiguration.
     */
    public void dispatchAnomaly(AnomalyAlert alert, AuditLoggerConfiguration config) {
        if (alert == null || config == null || !config.isEnableWebhookAlerts()) {
            return;
        }

        String eventType = "ANOMALY";
        String severity = alert.severity;
        String action = alert.type != null ? alert.type.name() : "";

        List<WebhookEndpoint> endpoints = config.resolveActiveEndpoints(eventType, severity, action);
        if (endpoints.isEmpty()) {
            return;
        }

        String jenkinsUrl = getJenkinsRootUrl();
        String isoTimestamp = Instant.ofEpochMilli(alert.timestamp).toString();
        String jsonPayload = buildAnomalyPayload(alert, jenkinsUrl, isoTimestamp);

        for (WebhookEndpoint ep : endpoints) {
            String url = ep.getPlainWebhookUrl();
            if (!url.isEmpty()) {
                executor.submit(() -> sendWithRetry(url, jsonPayload, 0));
            }
        }
    }

    /**
     * Dispatches a direct critical or high-priority audit log entry to matching webhook destinations.
     */
    public void dispatchAuditLog(AuditLogEntry entry, AuditLoggerConfiguration config) {
        if (entry == null || config == null || !config.isEnableWebhookAlerts()) {
            return;
        }

        String eventType = "AUDIT_LOG";
        String severity = entry.getSeverity();
        String action = entry.getAction();

        List<WebhookEndpoint> endpoints = config.resolveActiveEndpoints(eventType, severity, action);
        if (endpoints.isEmpty()) {
            return;
        }

        String jenkinsUrl = getJenkinsRootUrl();
        long entryTimeMs = entry.getTimestamp() > 0 ? entry.getTimestamp() : System.currentTimeMillis();
        String isoTimestamp = Instant.ofEpochMilli(entryTimeMs).toString();
        String jsonPayload = buildAuditLogPayload(entry, jenkinsUrl, isoTimestamp);

        for (WebhookEndpoint ep : endpoints) {
            String url = ep.getPlainWebhookUrl();
            if (!url.isEmpty()) {
                executor.submit(() -> sendWithRetry(url, jsonPayload, 0));
            }
        }
    }

    /**
     * Builds a comprehensive JSON payload for a direct audit log event, formatted
     * with Slack attachments, severity colors, and Microsoft Teams compatibility.
     */
    public String buildAuditLogPayload(AuditLogEntry entry, String jenkinsUrl, String isoTimestamp) {
        StringBuilder json = new StringBuilder();
        json.append("{");

        String severity = entry.getSeverity() != null ? entry.getSeverity() : "INFO";
        String user = entry.getUsername() != null ? entry.getUsername() : "SYSTEM";
        String action = entry.getAction() != null ? entry.getAction() : "";
        String details = entry.getDetails() != null ? entry.getDetails() : "";
        String target = entry.getTarget() != null ? entry.getTarget() : "";

        StringBuilder fallbackBuilder = new StringBuilder();
        fallbackBuilder.append("[AuditFlow Alert] ").append(severity).append(": ").append(action);
        fallbackBuilder.append(" - User: '").append(user).append("'");
        if (!details.isEmpty()) {
            fallbackBuilder.append(" | ").append(details);
        }
        if (jenkinsUrl != null && !jenkinsUrl.trim().isEmpty()) {
            fallbackBuilder.append(" (Jenkins: ").append(jenkinsUrl).append(")");
        }

        long timestampMs = entry.getTimestamp() > 0 ? entry.getTimestamp() : System.currentTimeMillis();

        json.append("\"type\":\"AUDIT_LOG\",");
        json.append("\"severity\":\"").append(escapeJson(severity)).append("\",");
        json.append("\"user\":\"").append(escapeJson(user)).append("\",");
        json.append("\"action\":\"").append(escapeJson(action)).append("\",");
        json.append("\"details\":\"").append(escapeJson(details)).append("\",");
        json.append("\"timestamp\":\"").append(isoTimestamp != null ? isoTimestamp : "").append("\",");
        json.append("\"timestampMs\":").append(timestampMs).append(",");
        json.append("\"jenkinsUrl\":\"").append(escapeJson(jenkinsUrl)).append("\",");
        json.append("\"source\":\"Jenkins Audit Logger\",");
        json.append("\"version\":\"1.0\",");

        String auditflowUrl = jenkinsUrl != null && !jenkinsUrl.trim().isEmpty()
                ? (jenkinsUrl.endsWith("/") ? jenkinsUrl + "manage/auditflow-logs/" : jenkinsUrl + "/manage/auditflow-logs/")
                : "";

        json.append("\"attachments\":[{");
        json.append("\"color\":\"").append(getSeverityColor(severity)).append("\",");
        json.append("\"fallback\":\"").append(escapeJson(fallbackBuilder.toString())).append("\",");
        json.append("\"title\":\"").append(escapeJson(getSeverityEmoji(severity) + " [AuditFlow Alert] "
                + severity + ": " + action)).append("\",");
        if (!auditflowUrl.isEmpty()) {
            json.append("\"title_link\":\"").append(escapeJson(auditflowUrl)).append("\",");
        }
        json.append("\"fields\":[");
        json.append("{\"title\":\"Severity\",\"value\":\"").append(escapeJson(severity)).append("\",\"short\":true},");
        json.append("{\"title\":\"User\",\"value\":\"").append(escapeJson(user)).append("\",\"short\":true},");
        json.append("{\"title\":\"Action\",\"value\":\"").append(escapeJson(action)).append("\",\"short\":true},");
        json.append("{\"title\":\"Timestamp\",\"value\":\"").append(escapeJson(isoTimestamp != null ? isoTimestamp : "")).append("\",\"short\":true}");
        if (!target.isEmpty()) {
            json.append(",{\"title\":\"Target\",\"value\":\"").append(escapeJson(target)).append("\",\"short\":true}");
        }
        if (!details.isEmpty()) {
            json.append(",{\"title\":\"Details\",\"value\":\"").append(escapeJson(formatDetailsForSlack(details))).append("\",\"short\":false}");
        }
        json.append("],");
        json.append("\"footer\":\"Jenkins AuditFlow\",");
        json.append("\"ts\":").append(timestampMs / 1000L);
        json.append("}]");
        json.append("}");

        return json.toString();
    }

    /**
     * Builds a comprehensive JSON payload for an anomaly alert.
     */
    public String buildAnomalyPayload(AnomalyAlert alert, String jenkinsUrl, String isoTimestamp) {
        StringBuilder json = new StringBuilder();
        json.append("{");

        String severity = alert.severity != null ? alert.severity : "HIGH";
        String user = alert.user != null ? alert.user : "SYSTEM";
        String readableType = alert.type != null ? getReadableAnomalyType(alert.type) : "Anomaly Alert";
        String details = alert.details != null ? alert.details : "";

        StringBuilder fallbackBuilder = new StringBuilder();
        fallbackBuilder.append("[AuditFlow Alert] ").append(severity).append(": ").append(readableType);
        fallbackBuilder.append(" - User: '").append(user).append("'");
        if (!details.isEmpty()) {
            fallbackBuilder.append(" | ").append(details);
        }
        if (jenkinsUrl != null && !jenkinsUrl.trim().isEmpty()) {
            fallbackBuilder.append(" (Jenkins: ").append(jenkinsUrl).append(")");
        }

        json.append("\"type\":\"").append(escapeJson(alert.type != null ? alert.type.name() : "")).append("\",");
        json.append("\"severity\":\"").append(escapeJson(severity)).append("\",");
        json.append("\"user\":\"").append(escapeJson(user)).append("\",");
        json.append("\"details\":\"").append(escapeJson(details)).append("\",");
        json.append("\"timestamp\":\"").append(isoTimestamp != null ? isoTimestamp : "").append("\",");
        json.append("\"timestampMs\":").append(alert.timestamp).append(",");
        json.append("\"jenkinsUrl\":\"").append(escapeJson(jenkinsUrl)).append("\",");
        json.append("\"alertId\":\"").append(escapeJson(alert.alertId)).append("\",");
        json.append("\"source\":\"Jenkins Audit Logger\",");
        json.append("\"version\":\"1.0\",");

        String auditflowUrl = jenkinsUrl != null && !jenkinsUrl.trim().isEmpty()
                ? (jenkinsUrl.endsWith("/") ? jenkinsUrl + "manage/auditflow-logs/" : jenkinsUrl + "/manage/auditflow-logs/")
                : "";

        json.append("\"attachments\":[{");
        json.append("\"color\":\"").append(getSeverityColor(severity)).append("\",");
        json.append("\"fallback\":\"").append(escapeJson(fallbackBuilder.toString())).append("\",");
        json.append("\"title\":\"").append(escapeJson(getSeverityEmoji(severity) + " [AuditFlow Alert] "
                + severity + ": " + readableType)).append("\",");
        if (!auditflowUrl.isEmpty()) {
            json.append("\"title_link\":\"").append(escapeJson(auditflowUrl)).append("\",");
        }
        json.append("\"fields\":[");
        json.append("{\"title\":\"Severity\",\"value\":\"").append(escapeJson(severity)).append("\",\"short\":true},");
        json.append("{\"title\":\"User\",\"value\":\"").append(escapeJson(user)).append("\",\"short\":true},");
        json.append("{\"title\":\"Anomaly Type\",\"value\":\"").append(escapeJson(alert.type != null ? alert.type.name() : "")).append("\",\"short\":true},");
        json.append("{\"title\":\"Timestamp\",\"value\":\"").append(escapeJson(isoTimestamp != null ? isoTimestamp : "")).append("\",\"short\":true},");
        json.append("{\"title\":\"Details\",\"value\":\"").append(escapeJson(formatDetailsForSlack(details))).append("\",\"short\":false}");
        json.append("],");
        json.append("\"footer\":\"Jenkins AuditFlow\",");
        json.append("\"ts\":").append(alert.timestamp / 1000L);
        json.append("}]");
        json.append("}");

        return json.toString();
    }

    /**
     * Performs HTTP POST dispatch with retry for transient rate limits (HTTP 429) and server errors (HTTP 5xx).
     */
    void sendWithRetry(String url, String json, int attempt) {
        if (url == null || url.trim().isEmpty()) {
            return;
        }
        try {
            HttpClient client = getHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                    .thenAccept(resp -> {
                        int code = resp.statusCode();
                        if (code >= 200 && code < 300) {
                            LOGGER.info("AuditFlow webhook successfully delivered to " + url + " (HTTP " + code + ")");
                        } else if ((code == 429 || code >= 500) && attempt < MAX_RETRIES) {
                            long delaySec = (long) Math.pow(2, attempt);
                            LOGGER.warning("Webhook returned HTTP " + code + " for " + url + ". Retrying in " + delaySec + "s (attempt " + (attempt + 1) + "/" + MAX_RETRIES + ")");
                            executor.schedule(() -> sendWithRetry(url, json, attempt + 1), delaySec, TimeUnit.SECONDS);
                        } else {
                            String snippet = resp.body() != null && !resp.body().trim().isEmpty() ? " - Response: " + resp.body().trim() : "";
                            LOGGER.warning("Webhook failed with HTTP " + code + " for " + url + snippet);
                        }
                    })
                    .exceptionally(ex -> {
                        if (attempt < MAX_RETRIES) {
                            long delaySec = (long) Math.pow(2, attempt);
                            LOGGER.warning("Webhook request failed for " + url + ": " + ex.getMessage() + ". Retrying in " + delaySec + "s");
                            executor.schedule(() -> sendWithRetry(url, json, attempt + 1), delaySec, TimeUnit.SECONDS);
                        } else {
                            LOGGER.log(Level.WARNING, "Webhook permanently failed for " + url + " after " + MAX_RETRIES + " attempts", ex);
                        }
                        return null;
                    });
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to initiate webhook request to " + url, e);
        }
    }

    public static String getSeverityColor(String severity) {
        if (severity == null) return "#1D9BD1";
        switch (severity.toUpperCase(Locale.ENGLISH)) {
            case "CRITICAL": return "#E01E5A";
            case "HIGH": return "#ECB22E";
            case "MEDIUM": return "#2EB886";
            default: return "#1D9BD1";
        }
    }

    public static String getSeverityEmoji(String severity) {
        if (severity == null) return "ℹ️";
        switch (severity.toUpperCase(Locale.ENGLISH)) {
            case "CRITICAL": return "🚨";
            case "HIGH": return "⚠️";
            case "MEDIUM": return "⚡";
            default: return "ℹ️";
        }
    }

    public static String formatDetailsForSlack(String details) {
        if (details == null) return "";
        return details.replaceAll("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b", "`$1`");
    }

    public static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    private static String getReadableAnomalyType(AnomalyType type) {
        if (type == null) return "Anomaly Alert";
        switch (type) {
            case BRUTE_FORCE_LOGIN:
                return "Suspicious Login Attempts (Brute Force)";
            case SUSPICIOUS_AUTH_PATTERN:
                return "Suspicious Authentication Pattern";
            case UNUSUAL_IP:
                return "Unusual IP Address Activity";
            case MULTI_IP_LOGIN:
                return "Concurrent Logins from Multiple IP Addresses";
            case ADMIN_PRIVILEGE_CHANGE:
                return "Admin Privilege / Security Change";
            case USER_LIFECYCLE_ANOMALY:
                return "User Account Creation / Deletion";
            case MASS_CHANGES:
                return "Mass Configuration Changes";
            case AFTER_HOURS_ADMIN:
                return "After-Hours Administrative Activity";
            case CREDENTIAL_EXPOSURE:
                return "Potential Credential Exposure";
            default:
                return type.name();
        }
    }

    private static String getJenkinsRootUrl() {
        Jenkins instance = Jenkins.getInstanceOrNull();
        if (instance != null) {
            String root = instance.getRootUrl();
            if (root != null) {
                return root;
            }
        }
        return "";
    }

    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(3, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
