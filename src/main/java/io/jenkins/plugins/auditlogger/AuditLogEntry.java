package io.jenkins.plugins.auditlogger;

import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;

import java.io.Serializable;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Immutable-after-construction audit log entry capturing Jenkins events with full context.
 * Thread-safe: uses DateTimeFormatter (vs SimpleDateFormat which is NOT thread-safe).
 */
public class AuditLogEntry implements Serializable {
    private static final long serialVersionUID = 3L;

    private static final DateTimeFormatter ISO_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter READABLE_FMT =
            DateTimeFormatter.ofPattern("MMM dd, yyyy HH:mm:ss").withZone(ZoneOffset.UTC);
    private static final Map<String, DateTimeFormatter> READABLE_FORMATTERS = new ConcurrentHashMap<>();

    private final long timestamp;
    private final String username;
    private final String action;
    private final String target;
    private volatile String details;
    private volatile String sourceIp;
    private volatile String authMethod;
    private volatile String triggerType;
    private volatile String sessionId;
    private volatile String userAgent;
    private volatile String severity;

    public AuditLogEntry(String username, String action, String target, String details) {
        this(username, action, target, details, System.currentTimeMillis());
    }

    /**
     * Constructor with explicit timestamp — used when restoring entries from disk.
     */
    AuditLogEntry(String username, String action, String target, String details, long timestamp) {
        if (action == null || action.trim().isEmpty()) {
            throw new IllegalArgumentException("Audit entry action cannot be null or empty");
        }
        if (target == null || target.trim().isEmpty()) {
            throw new IllegalArgumentException("Audit entry target cannot be null or empty");
        }
        this.timestamp = timestamp;
        this.username = username != null ? username.trim() : "SYSTEM";
        this.action = action.trim();
        this.target = target.trim();
        this.details = details != null ? details.trim() : "";
        this.severity = deriveSeverity(this.action);
        populateRequestContext();
    }

    /** Factory with explicit IP and auth method (for security listener). */
    public static AuditLogEntry withAuth(String username, String action, String target,
                                         String details, String sourceIp, String authMethod) {
        AuditLogEntry e = new AuditLogEntry(username, action, target, details);
        if (sourceIp != null && !sourceIp.isEmpty()) e.sourceIp = sourceIp;
        if (authMethod != null && !authMethod.isEmpty()) e.authMethod = authMethod;
        return e;
    }

    /** Factory for build events with trigger information. */
    public static AuditLogEntry withTrigger(String username, String action, String target,
                                            String details, String triggerType) {
        AuditLogEntry e = new AuditLogEntry(username, action, target, details);
        if (triggerType != null && !triggerType.isEmpty()) e.triggerType = triggerType;
        return e;
    }

    private void populateRequestContext() {
        StaplerRequest2 req = Stapler.getCurrentRequest2();
        if (req != null) {
            if (this.sourceIp == null) {
                this.sourceIp = extractClientIp(req);
            }
            this.userAgent = req.getHeader("User-Agent");
            if (req.getSession(false) != null) {
                this.sessionId = req.getSession(false).getId();
            }
            if (this.authMethod == null) {
                this.authMethod = detectAuthMethod(req);
            }
            if (this.sourceIp != null && this.username != null) {
                RequestHolder.cacheUserIp(this.username, this.sourceIp);
            }
        }
        if (this.sourceIp == null && this.username != null) {
            this.sourceIp = RequestHolder.getCachedUserIp(this.username);
        }
    }

    private static String extractClientIp(StaplerRequest2 req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return stripBrackets(xff.split(",")[0].trim());
        }
        String xRealIp = req.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return stripBrackets(xRealIp.trim());
        }
        return stripBrackets(req.getRemoteAddr());
    }

    private static String stripBrackets(String ip) {
        if (ip != null && ip.startsWith("[") && ip.endsWith("]")) {
            return ip.substring(1, ip.length() - 1);
        }
        return ip;
    }

    private static String detectAuthMethod(StaplerRequest2 req) {
        String authHeader = req.getHeader("Authorization");
        if (authHeader != null) {
            if (authHeader.startsWith("Basic ")) return "basic-auth";
            if (authHeader.startsWith("Bearer ")) return "bearer-token";
        }
        if (req.getSession(false) != null) return "session";
        return "unknown";
    }

    private static String deriveSeverity(String action) {
        if (action == null) return "INFO";
        // CRITICAL: security-breaking or irreversible actions
        if (action.contains("FAILED") || action.contains("DENIED") || action.contains("RESTART")
                || action.contains("SECURITY_CONFIG") || "NODE_LAUNCH_FAILURE".equals(action)
                || "CREDENTIAL_DELETED".equals(action) || "CREDENTIAL_CREATED".equals(action)
                || "JOB_DELETED".equals(action) || "BUILDS_PURGED".equals(action)
                || "AUTH_STRATEGY_CHANGED".equals(action) || "PLUGIN_REMOVED".equals(action)) return "CRITICAL";
        // HIGH: impactful changes requiring attention
        if (action.contains("DELETE") || action.contains("CREDENTIAL")
                || "BUILD_FAILED".equals(action) || "BUILD_ABORTED".equals(action)
                || "GLOBAL_CONFIG_UPDATED".equals(action)
                || "PLUGIN_DISABLED".equals(action) || "PLUGIN_ENABLED".equals(action)) return "HIGH";
        // LOW: successful authentication events, routine build and creation events
        if ("LOGIN".equals(action) || "LOGIN_SUCCESS".equals(action) || "LOGOUT".equals(action)
                || "SSO_LOGIN".equals(action) || "API_AUTH".equals(action)) return "LOW";
        // MEDIUM: configuration changes
        if (action.contains("SESSION_TERMINATED".equals(action) ? "SESSION_TERMINATED" : "CONFIG")
                || action.contains("PLUGIN") || "JOB_CONFIG_UPDATED".equals(action) || "JOB_RENAMED".equals(action)) return "MEDIUM";
        // LOW: routine build and creation events
        if (action.contains("BUILD") || action.contains("CREATED") || action.contains("ONLINE")) return "LOW";
        return "INFO";
    }

    // --- Getters ---

    public long getTimestamp()      { return timestamp; }
    public String getUsername()     { return username; }
    public String getAction()      { return action; }
    public String getTarget()      { return target; }
    public String getDetails()     { return details; }
    public String getSourceIp()    { return sourceIp; }
    public String getAuthMethod()  { return authMethod; }
    public String getTriggerType() { return triggerType; }
    public String getSessionId()   { return sessionId; }
    public String getUserAgent()   { return userAgent; }
    public String getSeverity()    { return severity; }

    // --- Setters ---

    public void setSourceIp(String sourceIp)      { this.sourceIp = sourceIp; }
    public void setAuthMethod(String authMethod)   { this.authMethod = authMethod; }
    public void setTriggerType(String triggerType) { this.triggerType = triggerType; }
    public void setSessionId(String sessionId)     { this.sessionId = sessionId; }
    public void setUserAgent(String userAgent)     { this.userAgent = userAgent; }
    public void setSeverity(String severity)       { this.severity = severity; }
    public void setDetails(String details)         { this.details = details; }

    /** ISO-8601 UTC timestamp. Thread-safe (DateTimeFormatter). */
    public String getFormattedTimestamp() {
        return ISO_FMT.format(Instant.ofEpochMilli(timestamp));
    }

    /** Human-readable UTC timestamp. Thread-safe. */
    public String getReadableTimestamp() {
        return READABLE_FMT.format(Instant.ofEpochMilli(timestamp));
    }

    /** Human-readable timestamp for a configured display timezone. */
    public String getReadableTimestamp(ZoneId zoneId) {
        ZoneId resolved = zoneId != null ? zoneId : ZoneOffset.UTC;
        DateTimeFormatter formatter = READABLE_FORMATTERS.computeIfAbsent(
                resolved.getId(),
                key -> DateTimeFormatter.ofPattern("MMM dd, yyyy HH:mm:ss").withZone(resolved));
        return formatter.format(Instant.ofEpochMilli(timestamp));
    }

    @Override
    public String toString() {
        return String.format("[%s] %s | %s | %s | %s | IP=%s | auth=%s | trigger=%s",
                getFormattedTimestamp(), username, action, target, details,
                sourceIp != null ? sourceIp : "-",
                authMethod != null ? authMethod : "-",
                triggerType != null ? triggerType : "-");
    }
}
