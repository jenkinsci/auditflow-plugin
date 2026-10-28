package io.jenkins.plugins.auditlogger;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTP session lifecycle listener.
 * Tracks session creation, timeout, and termination for audit purposes.
 *
 * Fix: IP/UA are NOT available from session attributes — we capture them
 * from the current request via RequestHolder when the session is associated with a user.
 */
public class AuditSessionListener implements HttpSessionListener {
    private static final Logger LOGGER = Logger.getLogger(AuditSessionListener.class.getName());
    private static final int MAX_TRACKED_SESSIONS = 50_000;

    private static final ConcurrentHashMap<String, SessionMetadata> activeSessions = new ConcurrentHashMap<>();

    static class SessionMetadata {
        final String sessionId;
        volatile String username;
        final long createdTime;
        volatile String sourceIp;
        volatile String userAgent;

        SessionMetadata(String sessionId, long createdTime) {
            this.sessionId = sessionId;
            this.createdTime = createdTime;
        }
    }

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        try {
            HttpSession session = event.getSession();
            String sessionId = session.getId();

            if (activeSessions.size() >= MAX_TRACKED_SESSIONS) {
                // Evict oldest 10%
                long cutoff = System.currentTimeMillis() - 24 * 3600 * 1000L;
                activeSessions.entrySet().removeIf(e -> e.getValue().createdTime < cutoff);
            }

            SessionMetadata metadata = new SessionMetadata(sessionId, System.currentTimeMillis());

            // Try to capture IP/UA from current request
            HttpServletRequest req = RequestHolder.get();
            if (req != null) {
                metadata.sourceIp = extractClientIp(req);
                metadata.userAgent = req.getHeader("User-Agent");
            }

            activeSessions.put(sessionId, metadata);
            LOGGER.fine("HTTP session created: " + sessionId);
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error tracking session creation", e);
        }
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        try {
            HttpSession session = event.getSession();
            String sessionId = session.getId();
            SessionMetadata metadata = activeSessions.remove(sessionId);

            if (metadata != null && metadata.username != null) {
                long durationMs = System.currentTimeMillis() - metadata.createdTime;
                String reason = durationMs > 15 * 60 * 1000 ? "INACTIVITY_TIMEOUT"
                        : durationMs < 5000 ? "IMMEDIATE_DISCONNECT" : "USER_LOGOUT";

                String ip = metadata.sourceIp;
                if ((ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) && metadata.username != null) {
                    String cached = RequestHolder.getCachedUserIp(metadata.username);
                    if (cached != null) ip = cached;
                }

                AuditLogEntry entry = new AuditLogEntry(
                        metadata.username, "SESSION_TERMINATED",
                        "HTTP Session",
                        String.format("Reason: %s | Duration: %d mins | IP: %s",
                                reason, durationMs / 60000,
                                ip != null ? ip : "unknown"));
                entry.setSourceIp(ip);
                entry.setUserAgent(metadata.userAgent);
                entry.setSessionId(sessionId);
                AuditLogStorage.getInstance().addEntry(entry);
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error tracking session destruction", e);
        }
    }

    public static void associateUsernameWithSession(String sessionId, String username) {
        associateSession(sessionId, username, null, null);
    }

    public static void associateSession(String sessionId, String username, String sourceIp, String userAgent) {
        activeSessions.computeIfPresent(sessionId, (k, metadata) -> {
            metadata.username = username;
            if ((metadata.sourceIp == null || metadata.sourceIp.isEmpty()) && sourceIp != null && !"unknown".equalsIgnoreCase(sourceIp) && !"N/A".equalsIgnoreCase(sourceIp)) {
                metadata.sourceIp = sourceIp;
            }
            if ((metadata.userAgent == null || metadata.userAgent.isEmpty()) && userAgent != null && !"N/A".equalsIgnoreCase(userAgent)) {
                metadata.userAgent = userAgent;
            }
            return metadata;
        });
    }

    public static int getActiveSessionCount() {
        return activeSessions.size();
    }

    public static Map<String, SessionMetadata> getActiveSessions() {
        return new ConcurrentHashMap<>(activeSessions);
    }

    private static String extractClientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) return xff.split(",")[0].trim();
        String xRealIp = req.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) return xRealIp.trim();
        return req.getRemoteAddr();
    }
}
