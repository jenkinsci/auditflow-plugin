package io.jenkins.plugins.auditlogger;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

/**
 * Analytics and metrics engine for audit logs. All maps are bounded.
 */
public class AuditMetricsEngine {

    private static final int MAX_ACTIONS_TRACKED = 1_000;
    private static final int MAX_USERS_TRACKED = 10_000;
    private static final int MAX_HOURLY_BUCKETS = 7 * 24; // 7 days

    private final ConcurrentHashMap<String, ActionMetrics> actionMetrics = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, UserMetrics> userMetrics = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LongAdder> hourlyEventCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> severityCounts = new ConcurrentHashMap<>();

    public static class ActionMetrics {
        private final String action;
        private final LongAdder count = new LongAdder();
        private final long firstSeen;
        private final ConcurrentHashMap<String, AtomicInteger> userFrequency = new ConcurrentHashMap<>();

        public ActionMetrics(String action) {
            this.action = action;
            this.firstSeen = System.currentTimeMillis();
        }
    }

    public static class UserMetrics {
        private final String username;
        private final LongAdder eventCount = new LongAdder();
        private final long firstActivity;
        private final Set<String> actionsPerformed = ConcurrentHashMap.newKeySet();
        private final Set<String> sourceIps = ConcurrentHashMap.newKeySet();
        private final AtomicInteger failedLogins = new AtomicInteger();
        private final AtomicInteger successfulLogins = new AtomicInteger();

        public UserMetrics(String username) {
            this.username = username;
            this.firstActivity = System.currentTimeMillis();
        }

        public double getFailureRate() {
            int total = failedLogins.get() + successfulLogins.get();
            return total == 0 ? 0.0 : (double) failedLogins.get() / total;
        }
    }

    public void record(AuditLogEntry entry) {
        if (entry == null) return;

        String action = entry.getAction() != null ? entry.getAction() : "UNKNOWN";
        String user = entry.getUsername() != null ? entry.getUsername() : "SYSTEM";

        if (actionMetrics.size() < MAX_ACTIONS_TRACKED || actionMetrics.containsKey(action)) {
            ActionMetrics am = actionMetrics.computeIfAbsent(action, ActionMetrics::new);
            am.count.increment();
            am.userFrequency.computeIfAbsent(user, ignored -> new AtomicInteger()).incrementAndGet();
        }

        if (userMetrics.size() < MAX_USERS_TRACKED || userMetrics.containsKey(user)) {
            UserMetrics um = userMetrics.computeIfAbsent(user, UserMetrics::new);
            um.eventCount.increment();
            if (um.actionsPerformed.size() < 200) um.actionsPerformed.add(action);
            if (entry.getSourceIp() != null && um.sourceIps.size() < 100) {
                um.sourceIps.add(entry.getSourceIp());
            }
            if ("FAILED_LOGIN".equals(action)) {
                um.failedLogins.incrementAndGet();
            } else if ("LOGIN".equals(action)) {
                um.successfulLogins.incrementAndGet();
            }
        }

        String hourKey = String.valueOf(entry.getTimestamp() / 3_600_000);
        hourlyEventCounts.computeIfAbsent(hourKey, ignored -> new LongAdder()).increment();
        pruneHourlyData();

        severityCounts.computeIfAbsent(
                entry.getSeverity() != null ? entry.getSeverity() : "INFO",
                ignored -> new AtomicInteger()).incrementAndGet();
    }

    private void pruneHourlyData() {
        if (hourlyEventCounts.size() > MAX_HOURLY_BUCKETS * 2) {
            long cutoff = (System.currentTimeMillis() - 7L * 24 * 3600 * 1000) / 3_600_000;
            hourlyEventCounts.entrySet().removeIf(e -> {
                try {
                    return Long.parseLong(e.getKey()) < cutoff;
                } catch (NumberFormatException ex) {
                    return true;
                }
            });
        }
    }

    public List<Map<String, Object>> getTopActions(int limit) {
        List<ActionMetrics> sorted = new ArrayList<>(actionMetrics.values());
        sorted.sort((a, b) -> Long.compare(b.count.sum(), a.count.sum()));
        List<Map<String, Object>> result = new ArrayList<>();
        for (int i = 0; i < Math.min(limit, sorted.size()); i++) {
            ActionMetrics m = sorted.get(i);
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("action", m.action);
            map.put("count", m.count.sum());
            map.put("uniqueUsers", m.userFrequency.size());
            result.add(map);
        }
        return result;
    }

    public List<Map<String, Object>> getTopUsers(int limit) {
        List<UserMetrics> sorted = new ArrayList<>(userMetrics.values());
        sorted.sort((a, b) -> Long.compare(b.eventCount.sum(), a.eventCount.sum()));
        List<Map<String, Object>> result = new ArrayList<>();
        for (int i = 0; i < Math.min(limit, sorted.size()); i++) {
            UserMetrics m = sorted.get(i);
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("username", m.username);
            map.put("eventCount", m.eventCount.sum());
            map.put("uniqueActions", m.actionsPerformed.size());
            map.put("sourceIps", m.sourceIps.size());
            map.put("failureRate", String.format("%.1f%%", m.getFailureRate() * 100));
            result.add(map);
        }
        return result;
    }

    public List<Map<String, Object>> getSuspiciousUsers(int limit) {
        List<UserMetrics> suspicious = new ArrayList<>();
        for (UserMetrics m : userMetrics.values()) {
            if (m.getFailureRate() > 0.3 || m.sourceIps.size() > 5 || m.eventCount.sum() > 1000) {
                suspicious.add(m);
            }
        }
        suspicious.sort((a, b) -> Double.compare(b.getFailureRate(), a.getFailureRate()));
        List<Map<String, Object>> result = new ArrayList<>();
        for (int i = 0; i < Math.min(limit, suspicious.size()); i++) {
            UserMetrics m = suspicious.get(i);
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("username", m.username);
            map.put("failureRate", String.format("%.1f%%", m.getFailureRate() * 100));
            map.put("sourceIps", m.sourceIps.size());
            map.put("eventCount", m.eventCount.sum());
            result.add(map);
        }
        return result;
    }

    public Map<String, Object> getSeverityDistribution() {
        Map<String, Object> dist = new LinkedHashMap<>();
        for (String sev : new String[]{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}) {
            dist.put(sev, severityCounts.getOrDefault(sev, new AtomicInteger()).get());
        }
        return dist;
    }

    public Map<String, Object> getDashboardMetrics() {
        Map<String, Object> metrics = new LinkedHashMap<>();
        long totalEvents = actionMetrics.values().stream().mapToLong(m -> m.count.sum()).sum();
        metrics.put("totalEvents", totalEvents);
        metrics.put("uniqueActions", actionMetrics.size());
        metrics.put("uniqueUsers", userMetrics.size());
        metrics.put("topActions", getTopActions(5));
        metrics.put("topUsers", getTopUsers(5));
        metrics.put("severityDistribution", getSeverityDistribution());
        metrics.put("suspiciousUsers", getSuspiciousUsers(5));
        return metrics;
    }

    public Map<String, Object> getComplianceMetrics() {
        Map<String, Object> c = new LinkedHashMap<>();
        long auth = safeCount("LOGIN") + safeCount("FAILED_LOGIN");
        long config = actionMetrics.values().stream()
                .filter(m -> m.action.contains("CONFIG") || m.action.contains("UPDATED"))
                .mapToLong(m -> m.count.sum()).sum();
        c.put("authenticationEvents", auth);
        c.put("configurationChanges", config);
        c.put("averageEventsPerUser",
                userMetrics.isEmpty() ? 0 :
                        userMetrics.values().stream().mapToLong(m -> m.eventCount.sum()).sum() / userMetrics.size());
        return c;
    }

    private long safeCount(String action) {
        ActionMetrics m = actionMetrics.get(action);
        return m != null ? m.count.sum() : 0;
    }
}
