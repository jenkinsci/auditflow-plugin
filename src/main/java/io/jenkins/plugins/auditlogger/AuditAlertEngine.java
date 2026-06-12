package io.jenkins.plugins.auditlogger;

import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Rule-based alert engine with throttling.
 * All collections bounded. Daemon threads for notifications. Proper shutdown.
 */
public class AuditAlertEngine {
    private static final Logger LOGGER = Logger.getLogger(AuditAlertEngine.class.getName());

    private static final long MIN_ALERT_INTERVAL_MS = 5 * 60 * 1000;
    private static final int MAX_PENDING_ALERTS = 10_000;
    private static final int MAX_THROTTLE_ENTRIES = 10_000;

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "Audit-Alert-Sender");
        t.setDaemon(true);
        return t;
    });
    private final ConcurrentHashMap<String, Long> lastAlertTime = new ConcurrentHashMap<>();
    private final List<AlertRule> rules = new CopyOnWriteArrayList<>();
    private final ConcurrentLinkedDeque<AuditAlert> pendingAlerts = new ConcurrentLinkedDeque<>();

    public static class AlertRule {
        public final String name;
        public final String condition;
        public final String notificationChannels;
        public final String recipients;
        public volatile boolean enabled = true;

        public AlertRule(String name, String condition, String channels, String recipients) {
            this.name = name;
            this.condition = condition;
            this.notificationChannels = channels;
            this.recipients = recipients;
        }
    }

    public static class AuditAlert {
        public final String alertId;
        public final String ruleId;
        public final AuditLogEntry triggeringEvent;
        public final long timestamp;
        public final String severity;
        public final String message;

        public AuditAlert(String ruleId, AuditLogEntry event, String message, String severity) {
            this.alertId = UUID.randomUUID().toString();
            this.ruleId = ruleId;
            this.triggeringEvent = event;
            this.timestamp = System.currentTimeMillis();
            this.severity = severity;
            this.message = message;
        }
    }

    public void addRule(AlertRule rule) {
        rules.add(rule);
    }

    public void evaluate(AuditLogEntry entry) {
        if (entry == null) return;
        for (AlertRule rule : rules) {
            if (!rule.enabled) continue;
            if (matchesCondition(entry, rule.condition)) {
                fireAlert(rule, entry);
            }
        }
    }

    private boolean matchesCondition(AuditLogEntry entry, String condition) {
        if (condition == null || condition.isEmpty()) return false;
        for (String part : condition.split("&")) {
            String[] kv = part.split("=", 2);
            if (kv.length != 2) continue;
            String key = kv[0].trim();
            String value = kv[1].trim();
            boolean matches;
            switch (key) {
                case "action":   matches = entry.getAction().contains(value); break;
                case "severity": matches = value.equals(entry.getSeverity()); break;
                case "user":     matches = value.equals(entry.getUsername()); break;
                case "target":   matches = entry.getTarget().contains(value); break;
                default:         matches = false;
            }
            if (!matches) return false;
        }
        return true;
    }

    private void fireAlert(AlertRule rule, AuditLogEntry entry) {
        String throttleKey = rule.name + ":" + entry.getUsername();
        long now = System.currentTimeMillis();
        Long last = lastAlertTime.get(throttleKey);
        if (last != null && (now - last) < MIN_ALERT_INTERVAL_MS) return;

        lastAlertTime.put(throttleKey, now);
        evictStaleThrottles(now);

        String message = String.format("Alert: %s | User: %s | Action: %s | Target: %s",
                rule.name, entry.getUsername(), entry.getAction(), entry.getTarget());
        AuditAlert alert = new AuditAlert(rule.name, entry, message, entry.getSeverity());

        pendingAlerts.addFirst(alert);
        while (pendingAlerts.size() > MAX_PENDING_ALERTS) {
            pendingAlerts.removeLast();
        }

        executor.submit(() -> sendNotifications(rule, alert));
    }

    private void evictStaleThrottles(long now) {
        if (lastAlertTime.size() > MAX_THROTTLE_ENTRIES) {
            long cutoff = now - MIN_ALERT_INTERVAL_MS * 4;
            lastAlertTime.entrySet().removeIf(e -> e.getValue() < cutoff);
        }
    }

    private void sendNotifications(AlertRule rule, AuditAlert alert) {
        if (rule.notificationChannels == null) return;
        for (String channel : rule.notificationChannels.split(",")) {
            channel = channel.trim();
            try {
                switch (channel) {
                    case "email":   
                        LOGGER.fine("Email alert to: " + rule.recipients); 
                        break;
                    case "slack":   
                        LOGGER.fine("Slack alert: " + alert.ruleId); 
                        // slack needs this json format, hope it works
                        String slackPayload = "{\"text\": \"" + alert.message.replace("\"", "\\\"") + "\"}";
                        sendWebhook(rule.recipients, slackPayload);
                        break;
                    case "teams":
                        LOGGER.fine("Teams alert: " + alert.ruleId);
                        // teams uses the exact same json text as slack, yay less work
                        String teamsPayload = "{\"text\": \"" + alert.message.replace("\"", "\\\"") + "\"}";
                        sendWebhook(rule.recipients, teamsPayload);
                        break;
                    case "webhook": 
                        LOGGER.fine("Webhook alert: " + rule.recipients); 
                        break;
                    default:        
                        LOGGER.fine("Unknown channel: " + channel);
                }
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to send alert via " + channel, e);
            }
        }
    }

    // sending it to the url here
    protected void sendWebhook(String urlString, String jsonPayload) throws Exception {
        if (urlString == null || urlString.isEmpty()) return;
        
        java.net.URL url = new java.net.URL(urlString);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        // setting the method to post
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true); // gotta set this to true to send body

        try (java.io.OutputStream os = conn.getOutputStream()) {
            byte[] input = jsonPayload.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        int responseCode = conn.getResponseCode();
        // check if it failed lol
        if (responseCode >= 400) {
            LOGGER.warning("Webhook failed with response code: " + responseCode);
        }
    }

    public List<AuditAlert> getPendingAlerts() {
        return new ArrayList<>(pendingAlerts);
    }

    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("activeRules", (int) rules.stream().filter(r -> r.enabled).count());
        stats.put("totalRules", rules.size());
        stats.put("pendingAlerts", pendingAlerts.size());
        return stats;
    }

    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
