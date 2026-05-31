package io.jenkins.plugins.auditlogger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Anomaly detection is temporarily disabled to keep the audit hot path lean.
 * This placeholder preserves the existing API surface for the dashboard code.
 
 */
public class AnomalyDetector {

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

        public AnomalyAlert(AnomalyType type, String user, String details, String severity) {
            this.type = type;
            this.user = user;
            this.details = details;
            this.timestamp = System.currentTimeMillis();
            this.severity = severity;
        }
    }

    // storing failed logins here. heard ConcurrentHashMap is good for thread safety stuff?
    private final ConcurrentHashMap<String, List<Long>> failedLogins = new ConcurrentHashMap<>();
    
    // storing our alerts here to send to the UI
    private final CopyOnWriteArrayList<AnomalyAlert> activeAlerts = new CopyOnWriteArrayList<>();

    public void analyze(AuditLogEntry entry) {
        // we only care about failed logins for now
        if ("FAILED_LOGIN".equals(entry.getAction())) {
            String user = entry.getUsername();
            long now = System.currentTimeMillis();
            
            // setup the list if this is their first fail
            failedLogins.putIfAbsent(user, new ArrayList<>());
            List<Long> times = failedLogins.get(user);
            
            // stackoverflow said we need to synchronize when iterating a normal ArrayList inside a concurrent map
            synchronized(times) {
                times.add(now);
                
                // 3. Count how many failures happened in the last 60 seconds (60,000 milliseconds)
                long oneMinuteAgo = now - 60000;
                int recentFailures = 0;
                
                for (Long time : times) {
                    if (time > oneMinuteAgo) {
                        recentFailures++;
                    }
                }
                
                // 4. If they failed 5 or more times, trigger an alert!
                if (recentFailures >= 5) {
                    AnomalyAlert alert = new AnomalyAlert(
                        AnomalyType.BRUTE_FORCE_LOGIN, 
                        user, 
                        "User failed to log in " + recentFailures + " times in 1 minute.", 
                        "CRITICAL"
                    );
                    
                    activeAlerts.add(alert);
                    
                    // Optional: clear the user's history so we don't spam duplicate alerts for the same attack
                    times.clear();
                }
            }
        }
    }
       

    public List<AnomalyAlert> getAlerts(int limit) {
        if (activeAlerts.isEmpty()) {
            return Collections.emptyList();
        }
        int max = Math.min(limit, activeAlerts.size());
        List<AnomalyAlert> result = new ArrayList<>(max);
        for (int i = 0; i < max; i++) {
            result.add(activeAlerts.get(i));
        }
        return result;
    }

    public void cleanupOldAlerts() {
        // Intentionally disabled.
    }

    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalAlerts", 0);
        stats.put("trackedUsers", 0);
        stats.put("trackedLogins", 0);
        return stats;
    }
}
