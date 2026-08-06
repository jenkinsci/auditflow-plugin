package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.Computer;
import hudson.model.TaskListener;
import hudson.model.User;
import hudson.slaves.ComputerListener;
import hudson.slaves.OfflineCause;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.kohsuke.stapler.Stapler;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Audit listener for Jenkins agent/computer online, offline, connect, disconnect, and launch events.
 */
@Extension
public class AuditComputerListener extends ComputerListener {
    private static final Logger LOGGER = Logger.getLogger(AuditComputerListener.class.getName());

    @Override
    public void onOnline(Computer c, TaskListener listener) {
        log("NODE_ONLINE", c, null);
    }

    @Override
    public void onOffline(Computer c, OfflineCause cause) {
        log("NODE_OFFLINE", c, formatCause(cause));
    }

    @Override
    public void onTemporarilyOnline(Computer c) {
        log("NODE_TEMPORARILY_ONLINE", c, null);
    }

    @Override
    public void onTemporarilyOffline(Computer c, OfflineCause cause) {
        log("NODE_TEMPORARILY_OFFLINE", c, formatCause(cause));
    }

    @Override
    public void onLaunchFailure(Computer c, TaskListener taskListener) {
        log("NODE_LAUNCH_FAILURE", c, null);
    }

    private void log(String action, Computer c, String causeMsg) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableNodeEvents()) {
                return;
            }

            String nodeName = computerName(c);

            String duplicateKey = "COMPUTER:" + action + ":" + nodeName;
            if (StartupPhaseManager.wasRecentlyLogged(duplicateKey)) {
                LOGGER.log(Level.FINE, "Skipping duplicate computer log for: {0}", duplicateKey);
                return;
            }
            StartupPhaseManager.markAsLogged(duplicateKey);

            String username = currentUser();

            String details;
            if ("NODE_TEMPORARILY_OFFLINE".equals(action)) {
                details = causeMsg != null && !causeMsg.isEmpty()
                        ? String.format("Node taken offline: %s (Reason: %s) by %s", nodeName, causeMsg, username)
                        : String.format("Node taken offline: %s by %s", nodeName, username);
            } else if ("NODE_TEMPORARILY_ONLINE".equals(action)) {
                details = String.format("Node brought online: %s by %s", nodeName, username);
            } else if ("NODE_OFFLINE".equals(action)) {
                details = causeMsg != null && !causeMsg.isEmpty()
                        ? String.format("Node offline: %s (Reason: %s)", nodeName, causeMsg)
                        : String.format("Node offline: %s", nodeName);
            } else if ("NODE_ONLINE".equals(action)) {
                details = String.format("Node online: %s", nodeName);
            } else if ("NODE_LAUNCH_FAILURE".equals(action)) {
                details = String.format("Node launch failed: %s", nodeName);
            } else {
                details = String.format("%s: %s", action, nodeName);
            }

            AuditLogEntry entry = new AuditLogEntry(username, action, nodeName, details);
            if ("NODE_TEMPORARILY_OFFLINE".equals(action) || "NODE_OFFLINE".equals(action) || "NODE_LAUNCH_FAILURE".equals(action)) {
                entry.setSeverity("HIGH");
            } else if ("NODE_TEMPORARILY_ONLINE".equals(action)) {
                entry.setSeverity("MEDIUM");
            } else {
                entry.setSeverity("LOW");
            }

            AuditLogStorage.getInstance().addEntry(entry);
            LOGGER.log(Level.INFO, "Computer Event: {0} on {1} by {2}", new Object[]{action, nodeName, username});
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error recording computer event: " + action, e);
        }
    }

    private static String computerName(Computer c) {
        if (c == null) return "built-in";
        String name = c.getName();
        return name == null || name.isBlank() ? "built-in" : name;
    }

    private static String formatCause(OfflineCause cause) {
        if (cause == null) return "";
        if (cause instanceof OfflineCause.UserCause userCause) {
            String reason = userCause.getReason();
            if (reason != null && !reason.isBlank()) {
                return reason.trim();
            }
        }
        String msg = cause.toString();
        if (msg == null || msg.isBlank()) return "";
        return msg.trim();
    }

    static String currentUser() {
        // 0. Try Basic Auth header from HTTP request
        try {
            HttpServletRequest req = RequestHolder.get();
            if (req != null) {
                String authHeader = req.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Basic ")) {
                    String decoded = new String(java.util.Base64.getDecoder().decode(authHeader.substring(6)), java.nio.charset.StandardCharsets.UTF_8);
                    String username = decoded.contains(":") ? decoded.substring(0, decoded.indexOf(':')) : decoded;
                    if (isRealUser(username)) return username;
                }
            }
        } catch (RuntimeException ignored) {}

        // 1. Try pre-chain authenticated user
        String requestUser = RequestHolder.getAuthenticatedUser();
        if (isRealUser(requestUser)) {
            return requestUser;
        }

        // 2. Try session-based Spring Security context or request user
        try {
            HttpServletRequest request = RequestHolder.get();
            if (request != null) {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    String sessionUser = extractUserFromSession(session);
                    if (isRealUser(sessionUser)) {
                        return sessionUser;
                    }
                }
                if (isRealUser(request.getRemoteUser())) {
                    return request.getRemoteUser();
                }
                Principal principal = request.getUserPrincipal();
                if (principal != null && isRealUser(principal.getName())) {
                    return principal.getName();
                }
            }
        } catch (RuntimeException ignored) {
            // Continue through remaining resolution mechanisms
        }

        // 3. Try Stapler request
        try {
            var request = Stapler.getCurrentRequest2();
            if (request != null) {
                if (isRealUser(request.getRemoteUser())) {
                    return request.getRemoteUser();
                }
                Principal principal = request.getUserPrincipal();
                if (principal != null && isRealUser(principal.getName())) {
                    return principal.getName();
                }
                String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Basic ")) {
                    String decoded = new String(java.util.Base64.getDecoder().decode(authHeader.substring(6)), java.nio.charset.StandardCharsets.UTF_8);
                    String username = decoded.contains(":") ? decoded.substring(0, decoded.indexOf(':')) : decoded;
                    if (isRealUser(username)) return username;
                }
                if (request.getSession(false) != null) {
                    String sessionUser = extractUserFromSession(request.getSession(false));
                    if (isRealUser(sessionUser)) return sessionUser;
                }
            }
        } catch (RuntimeException ignored) {}

        // 4. Try Jenkins User.current()
        try {
            User user = User.current();
            if (user != null && isRealUser(user.getId())) {
                return user.getId();
            }
        } catch (RuntimeException ignored) {}

        // 5. Try Spring SecurityContext
        try {
            var authentication = org.springframework.security.core.context.SecurityContextHolder
                    .getContext().getAuthentication();
            if (authentication != null && isRealUser(authentication.getName())) {
                return authentication.getName();
            }
        } catch (RuntimeException ignored) {}

        return "SYSTEM";
    }

    private static String extractUserFromSession(HttpSession session) {
        if (session == null) return null;
        String[] contextKeys = {"SPRING_SECURITY_CONTEXT", "ACEGI_SECURITY_CONTEXT"};
        for (String key : contextKeys) {
            try {
                Object context = session.getAttribute(key);
                if (context != null) {
                    Method getAuthentication = context.getClass().getMethod("getAuthentication");
                    Object authentication = getAuthentication.invoke(context);
                    if (authentication != null) {
                        Method getName = authentication.getClass().getMethod("getName");
                        String name = (String) getName.invoke(authentication);
                        if (isRealUser(name)) {
                            return name;
                        }
                    }
                }
            } catch (ReflectiveOperationException | RuntimeException ignored) {}
        }
        return null;
    }

    private static boolean isRealUser(String username) {
        return username != null
                && !username.isEmpty()
                && !"SYSTEM".equalsIgnoreCase(username)
                && !"anonymous".equalsIgnoreCase(username)
                && !"anonymousUser".equalsIgnoreCase(username);
    }
}
