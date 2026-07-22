package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.RestartListener;
import hudson.model.User;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.security.Principal;
import java.util.concurrent.atomic.AtomicLong;

@Extension
public class AuditRestartListener extends RestartListener {
    private static final long DUPLICATE_WINDOW_MS = 5_000L;
    private static final AtomicLong LAST_HANDLED_AT = new AtomicLong(0L);

    @Override
    public boolean isReadyToRestart() throws IOException, InterruptedException {
        return true;
    }

    @Override
    public void onRestart() {
        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        if (config != null && !config.isEnableSystemConfigEvents()) {
            return;
        }

        long now = System.currentTimeMillis();
        RequestHolder.PendingRestartContext pending = RequestHolder.consumePendingRestart();
        if (pending != null) {
            if (pending.requestLogged) {
                LAST_HANDLED_AT.set(now);
                return;
            }
            if (shouldSuppressDuplicateRestartLog(now)) {
                return;
            }
            logRestart(pending.username, pending.safeRestart, now);
            return;
        }

        String username = resolveCurrentUsername();
        if (!isMeaningfulUser(username) || shouldSuppressDuplicateRestartLog(now)) {
            return;
        }
        logRestart(username, isSafeRestartInProgress(), now);
    }

    /**
     * Some Update Center restarts bypass {@link #onRestart()}. The plugin stop
     * hook runs on that path, while the pending user context is still available.
     */
    static void logPendingRestartOnPluginStop() {
        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        if (config != null && !config.isEnableSystemConfigEvents()) {
            return;
        }

        RequestHolder.PendingRestartContext pending = RequestHolder.consumePendingRestart();
        if (pending == null || pending.requestLogged) {
            return;
        }
        logRestart(pending.username, pending.safeRestart, System.currentTimeMillis());
    }

    private static void logRestart(String username, boolean safeRestart, long timestamp) {
        String details = (safeRestart ? "Safe" : "Immediate") + " restart initiated by " + username;
        AuditLogEntry entry = new AuditLogEntry(username, "SYSTEM_RESTART", "Jenkins", details, timestamp);
        entry.setSeverity("CRITICAL");

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.addEntry(entry);
        storage.flushNow();
    }

    private static boolean shouldSuppressDuplicateRestartLog(long now) {
        while (true) {
            long previous = LAST_HANDLED_AT.get();
            if (now - previous < DUPLICATE_WINDOW_MS) {
                return true;
            }
            if (LAST_HANDLED_AT.compareAndSet(previous, now)) {
                return false;
            }
        }
    }

    static void resetForTests() {
        LAST_HANDLED_AT.set(0L);
    }

    private static boolean isSafeRestartInProgress() {
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins == null) {
                return false;
            }
            Object result = jenkins.getClass().getMethod("isPreparingSafeRestart").invoke(jenkins);
            return result instanceof Boolean && (Boolean) result;
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            return false;
        }
    }

    private static String resolveCurrentUsername() {
        String requestUser = RequestHolder.getAuthenticatedUser();
        if (isMeaningfulUser(requestUser)) {
            return requestUser;
        }

        try {
            StaplerRequest2 req = Stapler.getCurrentRequest2();
            if (req != null) {
                String remoteUser = req.getRemoteUser();
                if (isMeaningfulUser(remoteUser)) {
                    return remoteUser;
                }

                Principal principal = req.getUserPrincipal();
                if (principal != null && isMeaningfulUser(principal.getName())) {
                    return principal.getName();
                }
            }
        } catch (RuntimeException ignored) {
            // Fall through to other resolution strategies.
        }

        try {
            User user = User.current();
            if (user != null && isMeaningfulUser(user.getId())) {
                return user.getId();
            }
        } catch (RuntimeException ignored) {
            // Fall through to SecurityContext resolution.
        }

        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && isMeaningfulUser(auth.getName())) {
                return auth.getName();
            }
        } catch (RuntimeException ignored) {
            return null;
        }
        return null;
    }

    private static boolean isMeaningfulUser(String username) {
        return username != null
                && !username.isEmpty()
                && !"anonymous".equalsIgnoreCase(username)
                && !"anonymousUser".equalsIgnoreCase(username)
                && !"SYSTEM".equalsIgnoreCase(username);
    }
}
