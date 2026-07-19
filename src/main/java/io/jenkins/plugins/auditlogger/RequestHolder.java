package io.jenkins.plugins.auditlogger;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Thread-local holder for the current HTTP request, plus a cross-request
 * pending-auth-entry map for deferred User-Agent enrichment.
 *
 * The pending map is needed because form/SSO logins trigger authenticated2()
 * inside Spring Security's filter chain, which then sends a 302 redirect
 * without continuing to PluginServletFilter.  The browser follows the redirect,
 * and THAT request goes through AuditRequestCapture where we can read User-Agent.
 */
public final class RequestHolder {
    private static final Logger LOGGER = Logger.getLogger(RequestHolder.class.getName());
    private static final ThreadLocal<HttpServletRequest> CURRENT = new ThreadLocal<>();
    /** Authenticated username captured BEFORE chain.doFilter() - survives Jenkins SYSTEM impersonation. */
    private static final ThreadLocal<String> AUTHENTICATED_USER = new ThreadLocal<>();
    private static final long PENDING_RESTART_TTL_MS = 5 * 60_000L;
    private static final AtomicReference<PendingRestartContext> PENDING_RESTART = new AtomicReference<>();

    /**
     * Pending auth entries awaiting User-Agent enrichment, keyed by username.
     * Entries are stored by SecurityListener.authenticated2() when the HTTP request
     * is not yet available, and consumed by AuditRequestCapture on the next request
     * from the same authenticated user.
     */
    private static final ConcurrentHashMap<String, PendingEntry> PENDING_AUTH = new ConcurrentHashMap<>();
    private static final long PENDING_TTL_MS = 30_000; // 30 seconds

    static final class PendingEntry {
        final AuditLogEntry entry;
        final long createdAt;
        PendingEntry(AuditLogEntry entry) {
            this.entry = entry;
            this.createdAt = System.currentTimeMillis();
        }
        boolean isExpired() {
            return System.currentTimeMillis() - createdAt > PENDING_TTL_MS;
        }
    }

    static final class PendingRestartContext {
        final String username;
        final boolean safeRestart;
        final boolean requestLogged;
        final long createdAt;

        PendingRestartContext(String username, boolean safeRestart, boolean requestLogged) {
            this.username = username;
            this.safeRestart = safeRestart;
            this.requestLogged = requestLogged;
            this.createdAt = System.currentTimeMillis();
        }

        boolean isExpired() {
            return System.currentTimeMillis() - createdAt > PENDING_RESTART_TTL_MS;
        }
    }

    private RequestHolder() {}

    public static void set(HttpServletRequest request) {
        CURRENT.set(request);
    }

    public static HttpServletRequest get() {
        return CURRENT.get();
    }

    public static void clear() {
        CURRENT.remove();
        AUTHENTICATED_USER.remove();
    }

    /** Store the authenticated username before filter chain processing. */
    public static void setAuthenticatedUser(String username) {
        AUTHENTICATED_USER.set(username);
    }

    /** Get the pre-chain authenticated username (survives SYSTEM impersonation). */
    public static String getAuthenticatedUser() {
        return AUTHENTICATED_USER.get();
    }

<<<<<<< HEAD
    public static void rememberPendingRestart(String username, boolean safeRestart, boolean requestLogged) {
        if (!isMeaningfulUser(username)) {
            return;
        }

        PendingRestartContext current = PENDING_RESTART.get();
        if (current != null && !current.isExpired() && current.requestLogged && !requestLogged) {
            return;
        }

        PENDING_RESTART.set(new PendingRestartContext(username, safeRestart, requestLogged));
    }

    public static PendingRestartContext consumePendingRestart() {
        PendingRestartContext pending = PENDING_RESTART.getAndSet(null);
        if (pending == null || pending.isExpired()) {
            return null;
        }
        return pending;
    }

    public static void clearPendingRestart() {
        PENDING_RESTART.set(null);
    }

=======
>>>>>>> refs/remotes/origin/restart-logging-bugfix
    /** Cache of user -> last-known IP for resolving IPs in async contexts (build events). */
    private static final ConcurrentHashMap<String, String> USER_IP_CACHE = new ConcurrentHashMap<>();
    private static final int MAX_USER_IP_ENTRIES = 10_000;

    /** Cache a user's IP address from a known request context. */
    public static void cacheUserIp(String username, String ip) {
        if (username != null && ip != null && !ip.isEmpty() && !"N/A".equals(ip)) {
            if (USER_IP_CACHE.size() >= MAX_USER_IP_ENTRIES) {
                // Evict oldest half to prevent unbounded growth
                var it = USER_IP_CACHE.entrySet().iterator();
                int toRemove = MAX_USER_IP_ENTRIES / 2;
                while (it.hasNext() && toRemove-- > 0) { it.next(); it.remove(); }
            }
            USER_IP_CACHE.put(username, ip);
        }
    }

    /** Get the last-known IP for a user (from login/request). Returns null if unknown. */
    public static String getCachedUserIp(String username) {
        return username != null ? USER_IP_CACHE.get(username) : null;
    }

    private static final int MAX_PENDING_ENTRIES = 1000;

    /** Store an auth event entry for later enrichment, keyed by username. */
    public static void setPendingAuthEntry(String username, AuditLogEntry entry) {
        if (username == null || entry == null) return;
        // Hard cap to prevent memory exhaustion from login floods
        if (PENDING_AUTH.size() >= MAX_PENDING_ENTRIES) {
            evictExpired();
            if (PENDING_AUTH.size() >= MAX_PENDING_ENTRIES) {
                // Still full - force-flush the oldest entry
                var it = PENDING_AUTH.entrySet().iterator();
                if (it.hasNext()) {
                    var oldest = it.next();
                    it.remove();
                    flushPendingEntry(oldest.getValue().entry);
                }
            }
        }
        PENDING_AUTH.put(username, new PendingEntry(entry));
    }

    /** Consume (get and remove) the pending auth entry for a given username. Returns null if none/expired. */
    public static AuditLogEntry consumePendingAuthEntry(String username) {
        if (username == null) return null;
        PendingEntry pe = PENDING_AUTH.remove(username);
        if (pe == null) return null;
        if (pe.isExpired()) {
            // Expired - write as-is without enrichment
            return pe.entry;
        }
        return pe.entry;
    }

    /**
     * Drain all expired pending entries so they can be written to the log
     * even without enrichment. This prevents data loss when enrichment never happens
     * (e.g., form login where the redirect follow doesn't reach AuditRequestCapture).
     */
    public static List<AuditLogEntry> drainExpiredEntries() {
        List<AuditLogEntry> expired = new java.util.ArrayList<>();
        Iterator<Map.Entry<String, PendingEntry>> it = PENDING_AUTH.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, PendingEntry> e = it.next();
            if (e.getValue().isExpired()) {
                expired.add(e.getValue().entry);
                it.remove();
            }
        }
        return expired;
    }

    /** Evict entries older than TTL to prevent leaks. Writes expired entries to storage so they are not lost. */
    private static void evictExpired() {
        Iterator<Map.Entry<String, PendingEntry>> it = PENDING_AUTH.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, PendingEntry> e = it.next();
            if (e.getValue().isExpired()) {
                // Write to storage before evicting - never silently drop an audit event
                flushPendingEntry(e.getValue().entry);
                it.remove();
            }
        }
    }

    private static void flushPendingEntry(AuditLogEntry entry) {
        try {
            AuditLogStorage.getInstance().addEntry(entry);
        } catch (RuntimeException e) {
            LOGGER.log(Level.FINE, "Failed to flush a pending auth entry", e);
        }
    }

    private static boolean isMeaningfulUser(String username) {
        return username != null
                && !username.isEmpty()
                && !"anonymous".equalsIgnoreCase(username)
                && !"anonymousUser".equalsIgnoreCase(username)
                && !"SYSTEM".equalsIgnoreCase(username);
    }
}
