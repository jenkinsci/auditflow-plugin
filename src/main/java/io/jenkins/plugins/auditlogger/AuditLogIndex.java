package io.jenkins.plugins.auditlogger;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Multi-index for fast audit log queries. Bounded to prevent unbounded memory growth.
 * Indices by: time (hourly buckets), user, action, severity.
 */
public class AuditLogIndex {

    private static final int MAX_INDEX_ENTRIES_PER_KEY = 5_000;
    private static final int MAX_KEYS_PER_INDEX = 10_000;

    private final ConcurrentHashMap<String, List<AuditLogEntry>> userIndex = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<AuditLogEntry>> actionIndex = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<AuditLogEntry>> severityIndex = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<AuditLogEntry>> timeIndex = new ConcurrentHashMap<>();

    public void index(AuditLogEntry entry) {
        if (entry == null) return;

        addToIndex(timeIndex, getHourKey(entry.getTimestamp()), entry);
        addToIndex(userIndex, entry.getUsername(), entry);
        addToIndex(actionIndex, entry.getAction(), entry);
        addToIndex(severityIndex, entry.getSeverity() != null ? entry.getSeverity() : "INFO", entry);
    }

    private void addToIndex(ConcurrentHashMap<String, List<AuditLogEntry>> index,
                            String key, AuditLogEntry entry) {
        if (key == null) return;
        if (index.size() >= MAX_KEYS_PER_INDEX && !index.containsKey(key)) return;

        List<AuditLogEntry> list = index.computeIfAbsent(key, k -> new CopyOnWriteArrayList<>());
        list.add(entry);

        // Trim if too large (keep most recent)
        if (list.size() > MAX_INDEX_ENTRIES_PER_KEY) {
            // CopyOnWriteArrayList subList not supported for modification; rebuild
            List<AuditLogEntry> trimmed = new ArrayList<>(
                    list.subList(list.size() - MAX_INDEX_ENTRIES_PER_KEY, list.size()));
            index.put(key, new CopyOnWriteArrayList<>(trimmed));
        }
    }

    public List<AuditLogEntry> queryByUser(String username) {
        List<AuditLogEntry> entries = userIndex.get(username);
        return entries != null ? new ArrayList<>(entries) : Collections.emptyList();
    }

    public List<AuditLogEntry> queryByAction(String action) {
        List<AuditLogEntry> entries = actionIndex.get(action);
        return entries != null ? new ArrayList<>(entries) : Collections.emptyList();
    }

    public List<AuditLogEntry> queryBySeverity(String severity) {
        List<AuditLogEntry> entries = severityIndex.get(severity);
        return entries != null ? new ArrayList<>(entries) : Collections.emptyList();
    }

    public List<AuditLogEntry> queryByTime(long startMs, long endMs) {
        long startHour = startMs / 3_600_000;
        long endHour = endMs / 3_600_000;
        List<AuditLogEntry> results = new ArrayList<>();
        for (Map.Entry<String, List<AuditLogEntry>> e : timeIndex.entrySet()) {
            try {
                long hour = Long.parseLong(e.getKey());
                if (hour >= startHour && hour <= endHour) {
                    for (AuditLogEntry entry : e.getValue()) {
                        if (entry.getTimestamp() >= startMs && entry.getTimestamp() <= endMs) {
                            results.add(entry);
                        }
                    }
                }
            } catch (NumberFormatException ignored) {}
        }
        return results;
    }

    public List<AuditLogEntry> query(String username, String action,
                                     Long startTime, Long endTime, String severity) {
        List<AuditLogEntry> results = null;

        if (username != null && !username.isEmpty()) results = queryByUser(username);
        else if (action != null && !action.isEmpty()) results = queryByAction(action);
        else if (severity != null && !severity.isEmpty()) results = queryBySeverity(severity);
        else if (startTime != null && endTime != null) results = queryByTime(startTime, endTime);
        else return Collections.emptyList();

        return results.stream()
                .filter(e -> username == null || username.isEmpty() || (e.getUsername() != null && e.getUsername().equalsIgnoreCase(username)))
                .filter(e -> action == null || action.isEmpty() || matchesAction(e.getAction(), action))
                .filter(e -> severity == null || severity.isEmpty() || severity.equals(e.getSeverity()))
                .filter(e -> startTime == null || e.getTimestamp() >= startTime)
                .filter(e -> endTime == null || e.getTimestamp() <= endTime)
                .collect(Collectors.toList());
    }

    static boolean matchesAction(String entryAction, String requestedAction) {
        if (requestedAction == null || requestedAction.isEmpty()) {
            return true;
        }
        if (entryAction == null) {
            return false;
        }
        if (entryAction.equalsIgnoreCase(requestedAction)) {
            return true;
        }
        String cleanEntry = entryAction.startsWith("[CLI] ") ? entryAction.substring(6).trim() : entryAction;
        String cleanReq = requestedAction.startsWith("[CLI] ") ? requestedAction.substring(6).trim() : requestedAction;
        if (cleanEntry.equalsIgnoreCase(cleanReq)) {
            return true;
        }
        if (cleanEntry.replace(' ', '_').equalsIgnoreCase(cleanReq.replace(' ', '_'))) {
            return true;
        }
        if ("AUTH".equalsIgnoreCase(cleanReq)) {
            return cleanEntry.contains("LOGIN") || cleanEntry.contains("AUTH");
        }
        if ("USER".equalsIgnoreCase(cleanReq)) {
            return cleanEntry.startsWith("USER_") || cleanEntry.contains("USER");
        }
        if ("SECURITY".equalsIgnoreCase(cleanReq)) {
            return cleanEntry.contains("SECURITY") || cleanEntry.contains("PRIVILEGE")
                    || cleanEntry.contains("AUTH_STRATEGY") || cleanEntry.contains("ROLE_CONFIG");
        }
        return "SCRIPT_CONSOLE_ACCESS".equalsIgnoreCase(cleanReq)
                && "SCRIPT_CONSOLE_ACCESSED".equalsIgnoreCase(cleanEntry);
    }

    public void clear() {
        timeIndex.clear();
        userIndex.clear();
        actionIndex.clear();
        severityIndex.clear();
    }

    public Map<String, Integer> getStatistics() {
        Map<String, Integer> stats = new LinkedHashMap<>();
        stats.put("timeKeys", timeIndex.size());
        stats.put("users", userIndex.size());
        stats.put("actions", actionIndex.size());
        stats.put("severities", severityIndex.size());
        return stats;
    }

    private static String getHourKey(long timestamp) {
        return String.valueOf(timestamp / 3_600_000);
    }
}
