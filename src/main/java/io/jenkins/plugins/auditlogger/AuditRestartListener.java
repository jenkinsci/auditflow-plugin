package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.RestartListener;
import hudson.model.User;
import jenkins.model.Jenkins;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Logs restart events from Jenkins core's restart lifecycle instead of relying
 * on request-route capture, which can miss post-install restart flows.
 */
@Extension
public class AuditRestartListener extends RestartListener {
    private static final long RESTART_LOG_SUPPRESSION_MS = 5_000L;
    private static final AtomicLong LAST_RESTART_LOGGED_AT = new AtomicLong(0L);

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
        long previous = LAST_RESTART_LOGGED_AT.get();
        if ((now - previous) < RESTART_LOG_SUPPRESSION_MS && LAST_RESTART_LOGGED_AT.compareAndSet(previous, now)) {
            return;
        }
        LAST_RESTART_LOGGED_AT.set(now);

        String username = resolveCurrentUsername();
        boolean safeRestart = isSafeRestartInProgress();
        String detail = (safeRestart ? "Safe" : "Immediate") + " restart initiated by " + username;

        AuditLogEntry entry = new AuditLogEntry(username, "SYSTEM_RESTART", "Jenkins", detail, now);
        entry.setSeverity("CRITICAL");

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.addEntry(entry);
        storage.flushNow();
    }

    private static boolean isSafeRestartInProgress() {
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins == null) {
                return false;
            }
            java.lang.reflect.Method method = jenkins.getClass().getMethod("isPreparingSafeRestart");
            Object result = method.invoke(jenkins);
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
            // Fall through to default.
        }

        return "SYSTEM";
    }

    private static boolean isMeaningfulUser(String user) {
        return user != null
                && !user.isEmpty()
                && !"anonymous".equalsIgnoreCase(user)
                && !"anonymousUser".equalsIgnoreCase(user)
                && !"SYSTEM".equalsIgnoreCase(user);
    }
}
