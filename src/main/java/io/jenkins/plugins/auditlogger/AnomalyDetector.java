package io.jenkins.plugins.auditlogger;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

import hudson.tasks.Mailer;
import jakarta.mail.Message;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

/**
 * Lightweight anomaly detection for dashboard alerts.
 *
 * Failed-login detection is intentionally simple, bounded, and configurable so
 * it can run safely on the audit ingest path without accumulating unbounded
 * state.
 */
public class AnomalyDetector {
    private static final int DEFAULT_FAILED_LOGIN_THRESHOLD = 5;
    private static final int DEFAULT_FAILED_LOGIN_WINDOW_MINUTES = 15;
    private static final int MAX_TRACKED_USERS = 10_000;
    private static final int MAX_ALERTS = 1_000;
    private static final long ALERT_RETENTION_MS = 24L * 60L * 60L * 1000L;
    private static final long CLEANUP_INTERVAL_MS = 60L * 1000L;

    private static final Logger LOGGER = Logger.getLogger(AnomalyDetector.class.getName());

    public enum AnomalyType {
        BRUTE_FORCE_LOGIN, UNUSUAL_IP, MASS_CHANGES,
        AFTER_HOURS_ADMIN, CREDENTIAL_EXPOSURE
    }

    public static class AnomalyAlert {
        public final AnomalyType type;
        public final String user;
        public final String details;
        public final long timestamp;
        public final String severity;
        public final String alertId;

        private volatile boolean dismissed;

        public AnomalyAlert(AnomalyType type, String user, String details, String severity) {
            this(type, user, details, severity, System.currentTimeMillis());
        }

        AnomalyAlert(AnomalyType type, String user, String details, String severity, long timestamp) {
            this.type = type;
            this.user = user;
            this.details = details;
            this.timestamp = timestamp;
            this.severity = severity;
            this.alertId = generateAlertId();
            this.dismissed = false;
        }

        public boolean isDismissed() {
            return dismissed;
        }

        public void dismiss() {
            this.dismissed = true;
        }

        private String generateAlertId() {
            return "auditflow-" + type.name() + "-" + user + "-" + timestamp;
        }
    }

    private static final class FailedLoginWindow {
        private final ArrayDeque<Long> timestamps = new ArrayDeque<>();
        private long lastObserved;
    }

    private final ConcurrentHashMap<String, FailedLoginWindow> failedLogins = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<AnomalyAlert> activeAlerts = new CopyOnWriteArrayList<>();
    private final AtomicLong lastCleanup = new AtomicLong(0L);

    public void analyze(AuditLogEntry entry) {
        analyze(entry, AuditLoggerConfiguration.get());
    }

    public void analyze(AuditLogEntry entry, AuditLoggerConfiguration config) {
        if (entry == null || !"FAILED_LOGIN".equals(entry.getAction())) {
            return;
        }

        // Anomaly detection is DISABLED by default; only enable if explicitly configured
        boolean detectionEnabled = config != null && config.isAnomalyFailedLogins();
        if (!detectionEnabled) {
            maybeCleanup(entry.getTimestamp(),
                    config != null ? config.getAnomalyFailedLoginsWindowMinutes() : DEFAULT_FAILED_LOGIN_WINDOW_MINUTES);
            return;
        }

        int threshold = config != null
                ? config.getAnomalyFailedLoginsThreshold()
                : DEFAULT_FAILED_LOGIN_THRESHOLD;
        int windowMinutes = config != null
                ? config.getAnomalyFailedLoginsWindowMinutes()
                : DEFAULT_FAILED_LOGIN_WINDOW_MINUTES;

        threshold = Math.max(2, threshold);
        windowMinutes = Math.max(1, windowMinutes);

        String user = entry.getUsername() != null ? entry.getUsername() : "UNKNOWN";
        long eventTime = entry.getTimestamp();
        long cutoff = eventTime - windowMinutes * 60_000L;

        FailedLoginWindow window = failedLogins.computeIfAbsent(user, ignored -> new FailedLoginWindow());
        int recentFailures;
        synchronized (window) {
            window.lastObserved = eventTime;
            while (!window.timestamps.isEmpty() && window.timestamps.peekFirst() <= cutoff) {
                window.timestamps.removeFirst();
            }
            window.timestamps.addLast(eventTime);
            recentFailures = window.timestamps.size();
            if (recentFailures >= threshold) {
                AnomalyAlert alert = new AnomalyAlert(
                        AnomalyType.BRUTE_FORCE_LOGIN,
                        user,
                        "Multiple failed logins detected for \"" + user + "\" ("
                            + recentFailures + " attempts in "
                            + windowMinutes + " minute" + (windowMinutes == 1 ? "" : "s") + ").",
                        "CRITICAL");
                activeAlerts.add(alert);
                trimAlerts();

                if (config != null && config.isEnableEmailAlerts()) {
                    sendEmailNotification(alert, config.getAlertEmailAddresses());
                }
                if (config != null && config.isEnableWebhookAlerts()) {
                    sendWebhookNotification(alert, config.getWebhookUrl());
                }
                if (config != null && config.isEnableSlackAlerts()) {
                    sendSlackNotification(alert, config.getSlackWebhookUrl());
                }
                if (config != null && config.isEnableTeamsAlerts()) {
                    sendTeamsNotification(alert, config.getTeamsWebhookUrl());
                }

                // Start a fresh counting window after each alert so a later burst
                // can raise a new alert without spamming every subsequent failure.
                window.timestamps.clear();
            }
        }

        maybeCleanup(eventTime, windowMinutes);
    }

    public List<AnomalyAlert> getAlerts(int limit) {
        if (limit <= 0 || activeAlerts.isEmpty()) {
            return Collections.emptyList();
        }

        int size = activeAlerts.size();
        List<AnomalyAlert> recentOpenAlerts = new ArrayList<>(Math.min(size, limit));
        for (int i = size - 1; i >= 0 && recentOpenAlerts.size() < limit; i--) {
            AnomalyAlert alert = activeAlerts.get(i);
            if (!alert.isDismissed()) {
                recentOpenAlerts.add(alert);
            }
        }
        Collections.reverse(recentOpenAlerts);
        return recentOpenAlerts;
    }

    public boolean dismissAlert(String alertId) {
        if (alertId == null || alertId.trim().isEmpty()) {
            return false;
        }

        for (AnomalyAlert alert : activeAlerts) {
            if (alert.alertId.equals(alertId)) {
                if (!alert.isDismissed()) {
                    alert.dismiss();
                }
                return true;
            }
        }
        return false;
    }

    public void cleanupOldAlerts() {
        cleanupOldAlerts(System.currentTimeMillis(), DEFAULT_FAILED_LOGIN_WINDOW_MINUTES);
    }

    public Map<String, Object> getStatistics() {
        int trackedLogins = 0;
        for (FailedLoginWindow window : failedLogins.values()) {
            synchronized (window) {
                trackedLogins += window.timestamps.size();
            }
        }

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalAlerts", activeAlerts.size());
        stats.put("trackedUsers", failedLogins.size());
        stats.put("trackedLogins", trackedLogins);
        return stats;
    }

    private void maybeCleanup(long eventTime, int windowMinutes) {
        long previous = lastCleanup.get();
        if ((eventTime - previous) < CLEANUP_INTERVAL_MS) {
            return;
        }
        if (lastCleanup.compareAndSet(previous, eventTime)) {
            cleanupOldAlerts(eventTime, windowMinutes);
        }
    }

    private void cleanupOldAlerts(long now, int windowMinutes) {
        long alertCutoff = now - ALERT_RETENTION_MS;
        activeAlerts.removeIf(alert -> alert.timestamp < alertCutoff);

        long staleWindowCutoff = now - Math.max(1, windowMinutes) * 60_000L;
        failedLogins.entrySet().removeIf(entry -> {
            FailedLoginWindow window = entry.getValue();
            synchronized (window) {
                while (!window.timestamps.isEmpty() && window.timestamps.peekFirst() <= staleWindowCutoff) {
                    window.timestamps.removeFirst();
                }
                return window.timestamps.isEmpty() && window.lastObserved <= staleWindowCutoff;
            }
        });

        if (failedLogins.size() > MAX_TRACKED_USERS) {
            List<Map.Entry<String, FailedLoginWindow>> candidates = new ArrayList<>(failedLogins.entrySet());
            candidates.sort((left, right) -> Long.compare(left.getValue().lastObserved, right.getValue().lastObserved));
            int removeCount = failedLogins.size() - MAX_TRACKED_USERS;
            for (int i = 0; i < removeCount && i < candidates.size(); i++) {
                failedLogins.remove(candidates.get(i).getKey(), candidates.get(i).getValue());
            }
        }
    }

    private void trimAlerts() {
        while (activeAlerts.size() > MAX_ALERTS) {
            activeAlerts.remove(0);
        }
    }

    private void sendEmailNotification(AnomalyAlert alert, String emailAddresses) {
        if (emailAddresses == null || emailAddresses.trim().isEmpty()) {
            return;
        }
        
        // Validate alert and email addresses
        List<String> alertErrors = AnomalyAlertValidator.validateAlert(alert);
        List<String> emailErrors = AnomalyAlertValidator.validateEmailAddresses(emailAddresses);
        
        List<String> criticalErrors = new ArrayList<>();
        criticalErrors.addAll(AnomalyAlertValidator.getCriticalErrors(alertErrors));
        criticalErrors.addAll(AnomalyAlertValidator.getCriticalErrors(emailErrors));
        
        if (!criticalErrors.isEmpty()) {
            LOGGER.warning("Email validation failed: " + String.join("; ", criticalErrors));
            return;
        }
        
        try {
            Mailer.DescriptorImpl mailerDescriptor = Mailer.descriptor();
            if (mailerDescriptor == null) {
                LOGGER.warning("Mailer plugin is not available. Cannot send anomaly email.");
                return;
            }
            
            // Note: Mailer.descriptor().createSession() uses the Jenkins global SMTP config
            MimeMessage msg = new MimeMessage(mailerDescriptor.createSession());
            msg.setSubject("Suspicious login attempts detected in Jenkins");
            
            // Format timestamp for readability
            String formattedTimestamp = formatTimestamp(alert.timestamp);
            
            String jenkinsUrl = "";
            jenkins.model.Jenkins instance = jenkins.model.Jenkins.getInstanceOrNull();
            if (instance != null) {
                String rootUrl = instance.getRootUrl();
                if (rootUrl != null) {
                    jenkinsUrl = rootUrl;
                }
            }
            
            // Enhanced email body with professional formatting
            String emailBody = formatAnomalyEmailBody(alert, formattedTimestamp, jenkinsUrl);
            msg.setText(emailBody);
            
            String adminAddress = mailerDescriptor.getAdminAddress();
            if (adminAddress != null && !adminAddress.trim().isEmpty()) {
                msg.setFrom(new InternetAddress(adminAddress));
            } else {
                msg.setFrom(new InternetAddress("auditflow@localhost"));
            }

            for (String to : emailAddresses.split(",")) {
                if (!to.trim().isEmpty()) {
                    msg.addRecipient(Message.RecipientType.TO, new InternetAddress(to.trim()));
                }
            }
            sendEmail(msg);
            LOGGER.info("Successfully sent anomaly email alert to " + emailAddresses);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to send anomaly email alert", e);
        }
    }

    /** Protected for testing */
    protected void sendEmail(MimeMessage msg) throws Exception {
        Transport.send(msg);
    }

    private void sendWebhookNotification(AnomalyAlert alert, String webhookUrl) {
        if (webhookUrl == null || webhookUrl.trim().isEmpty()) {
            return;
        }
        
        // Validate alert and webhook URL
        List<String> alertErrors = AnomalyAlertValidator.validateAlert(alert);
        List<String> urlErrors = AnomalyAlertValidator.validateWebhookUrl(webhookUrl);
        
        List<String> criticalErrors = new ArrayList<>();
        criticalErrors.addAll(AnomalyAlertValidator.getCriticalErrors(alertErrors));
        criticalErrors.addAll(AnomalyAlertValidator.getCriticalErrors(urlErrors));
        
        if (!criticalErrors.isEmpty()) {
            LOGGER.warning("Webhook validation failed: " + String.join("; ", criticalErrors));
            return;
        }
        
        try {
            String jenkinsUrl = "";
            jenkins.model.Jenkins instance = jenkins.model.Jenkins.getInstanceOrNull();
            if (instance != null) {
                String rootUrl = instance.getRootUrl();
                if (rootUrl != null) {
                    jenkinsUrl = rootUrl;
                }
            }

            // Format timestamp for webhook
            String isoTimestamp = Instant.ofEpochMilli(alert.timestamp)
                    .toString();
            
            // Build comprehensive JSON payload
            String json = buildWebhookPayload(alert, jenkinsUrl, isoTimestamp);
            
            // Validate payload before sending
            List<String> payloadErrors = AnomalyAlertValidator.validateWebhookPayload(json);
            if (!AnomalyAlertValidator.getCriticalErrors(payloadErrors).isEmpty()) {
                LOGGER.warning("Webhook payload validation failed: " + 
                        String.join("; ", AnomalyAlertValidator.getCriticalErrors(payloadErrors)));
                return;
            }

            sendWebhook(webhookUrl.trim(), json);
            LOGGER.info("Successfully sent anomaly webhook alert to " + webhookUrl);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to send anomaly webhook alert", e);
        }
    }

    private void sendSlackNotification(AnomalyAlert alert, String webhookUrl) {
        if (webhookUrl == null || webhookUrl.trim().isEmpty()) return;
        try {
            String text = "Jenkins AuditFlow Anomaly: " + alert.type + " - " + alert.details + " (User: " + alert.user + ")";
            String json = "{\"text\":\"" + escapeJson(text) + "\"}";
            sendWebhook(webhookUrl.trim(), json);
            LOGGER.info("Successfully sent anomaly Slack alert");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to send anomaly Slack alert", e);
        }
    }

    private void sendTeamsNotification(AnomalyAlert alert, String webhookUrl) {
        if (webhookUrl == null || webhookUrl.trim().isEmpty()) return;
        try {
            String text = "Jenkins AuditFlow Anomaly: " + alert.type + " - " + alert.details + " (User: " + alert.user + ")";
            String json = "{\"text\":\"" + escapeJson(text) + "\"}";
            sendWebhook(webhookUrl.trim(), json);
            LOGGER.info("Successfully sent anomaly Teams alert");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to send anomaly Teams alert", e);
        }
    }

    /** Protected for testing */
    protected void sendWebhook(String url, String json) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenAccept(resp -> {
                    if (resp.statusCode() >= 400) {
                        LOGGER.warning("Webhook returned HTTP " + resp.statusCode() + " for " + url);
                    }
                })
                .exceptionally(ex -> {
                    LOGGER.log(Level.WARNING, "Webhook async request failed for " + url, ex);
                    return null;
                });
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
    
    /**
     * Formats an anomaly alert into a professional email body.
     * @param alert the anomaly alert
     * @param formattedTimestamp the formatted timestamp string
     * @param jenkinsUrl the Jenkins instance URL
     * @return formatted email body
     */
    private String formatAnomalyEmailBody(AnomalyAlert alert, String formattedTimestamp, String jenkinsUrl) {
        StringBuilder body = new StringBuilder();

        body.append("Anomaly Detected in Jenkins AuditFlow\n\n");
        if (jenkinsUrl != null && !jenkinsUrl.trim().isEmpty()) {
            body.append("Jenkins URL: ").append(jenkinsUrl).append("\n\n");
        }
        body.append("Type: ").append(getReadableAnomalyType(alert.type)).append("\n");
        body.append("Severity: ").append(alert.severity).append("\n");
        body.append("User: ").append(alert.user).append("\n");
        body.append("Timestamp: ").append(formattedTimestamp).append("\n\n");
        
        body.append("Details:\n");
        body.append(alert.details).append("\n\n");

        body.append("Review the AuditFlow logs in Jenkins for additional details.\n");

        return body.toString();
    }
    
    /**
     * Builds a comprehensive webhook JSON payload.
     * @param alert the anomaly alert
     * @param jenkinsUrl the Jenkins instance URL
     * @param isoTimestamp the ISO 8601 formatted timestamp
     * @return JSON payload string
     */
    private String buildWebhookPayload(AnomalyAlert alert, String jenkinsUrl, String isoTimestamp) {
        // Build JSON with proper escaping
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"type\":\"").append(escapeJson(alert.type.name())).append("\",");
        json.append("\"severity\":\"").append(escapeJson(alert.severity)).append("\",");
        json.append("\"user\":\"").append(escapeJson(alert.user)).append("\",");
        json.append("\"details\":\"").append(escapeJson(alert.details)).append("\",");
        json.append("\"timestamp\":\"").append(isoTimestamp).append("\",");
        json.append("\"timestampMs\":").append(alert.timestamp).append(",");
        json.append("\"jenkinsUrl\":\"").append(escapeJson(jenkinsUrl)).append("\",");
        json.append("\"alertId\":\"").append(escapeJson(alert.alertId)).append("\",");
        json.append("\"source\":\"Jenkins Audit Logger\",");
        json.append("\"version\":\"1.0\"");
        json.append("}");
        return json.toString();
    }
    
    /**
     * Returns a human-readable description of an anomaly type.
     * @param type the anomaly type
     * @return readable description
     */
    private String getReadableAnomalyType(AnomalyType type) {
        switch (type) {
            case BRUTE_FORCE_LOGIN:
                return "Brute Force Login Attempt";
            case UNUSUAL_IP:
                return "Unusual IP Address";
            case MASS_CHANGES:
                return "Mass Configuration Changes";
            case AFTER_HOURS_ADMIN:
                return "After-Hours Admin Activity";
            case CREDENTIAL_EXPOSURE:
                return "Credential Exposure Risk";
            default:
                return type.name();
        }
    }
    
    /**
     * Formats a timestamp in milliseconds to ISO 8601 format with timezone.
     * @param timestamp the timestamp in milliseconds since epoch
     * @return formatted timestamp string
     */
    private String formatTimestamp(long timestamp) {
        try {
            Instant instant = Instant.ofEpochMilli(timestamp);
            ZoneId zoneId = ZoneId.of("UTC");
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss Z")
                    .withZone(zoneId);
            return formatter.format(instant) + " UTC";
        } catch (Exception e) {
            return new java.util.Date(timestamp).toString();
        }
    }
}
