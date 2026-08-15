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
        StartupPhaseManager.markAsLogged("COMPUTER:RECENT_STATUS_CHANGE:" + computerName(c));
        log("NODE_ONLINE", c, null);
    }

    @Override
    public void onTemporarilyOffline(Computer c, OfflineCause cause) {
        StartupPhaseManager.markAsLogged("COMPUTER:RECENT_STATUS_CHANGE:" + computerName(c));
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
            String username = currentUser();

            // Suppress non-real user events (SYSTEM background loading) ONLY during startup grace period when no request is active
            boolean hasRequest = RequestHolder.get() != null || Stapler.getCurrentRequest2() != null;
            if (!isRealUser(username) && (!hasRequest && StartupPhaseManager.isInStartupGracePeriod())) {
                LOGGER.log(Level.FINE, "Suppressing non-real user computer event: {0} on {1}",
                        new Object[]{action, nodeName});
                return;
            }

            // Suppress automatic NODE_ONLINE following a node configuration save
            if ("NODE_ONLINE".equals(action)) {
                if (StartupPhaseManager.wasRecentlyLogged("NODE_UPDATED_RECENT:" + nodeName)) {
                    LOGGER.log(Level.FINE, "Suppressing automatic NODE_ONLINE following node configuration update for: {0}", nodeName);
                    return;
                }
            }

            String duplicateKey = "COMPUTER:" + action + ":" + nodeName;
            if (StartupPhaseManager.wasRecentlyLogged(duplicateKey)) {
                LOGGER.log(Level.FINE, "Skipping duplicate computer log for: {0}", duplicateKey);
                return;
            }
            StartupPhaseManager.markAsLogged(duplicateKey);

            String details;
            if ("NODE_TEMPORARILY_OFFLINE".equals(action)) {
                details = causeMsg != null && !causeMsg.isEmpty()
                        ? String.format("Node taken offline: %s (Reason: %s) by %s", nodeName, causeMsg, username)
                        : String.format("Node taken offline: %s by %s", nodeName, username);
            } else if ("NODE_ONLINE".equals(action) || "NODE_TEMPORARILY_ONLINE".equals(action)) {
                details = String.format("Node brought online: %s by %s", nodeName, username);
            } else if ("NODE_OFFLINE".equals(action)) {
                details = causeMsg != null && !causeMsg.isEmpty()
                        ? String.format("Node disconnected: %s (Reason: %s)", nodeName, causeMsg)
                        : String.format("Node disconnected: %s", nodeName);
            } else if ("NODE_LAUNCH_FAILURE".equals(action)) {
                details = causeMsg != null && !causeMsg.isEmpty()
                        ? String.format("Node launch failed: %s (%s)", nodeName, causeMsg)
                        : String.format("Node launch failed: %s", nodeName);
            } else {
                details = String.format("%s: %s", action, nodeName);
            }

            boolean isCli = false;
            String cliCmdName = null;
            try {
                jenkins.cli.CLICommand cliCmd = jenkins.cli.CLICommand.getCLICommand();
                if (cliCmd != null) {
                    isCli = true;
                    cliCmdName = cliCmd.getName();
                }
            } catch (Throwable ignored) {}

            if (!isCli) {
                AsyncActionTracker.CliAction cliAction = AsyncActionTracker.getInstance().resolveAction(nodeName, System.currentTimeMillis());
                if (cliAction != null && (username == null || cliAction.username.equals(username))) {
                    isCli = true;
                    cliCmdName = cliAction.command;
                }
            }

            String baseAction = action;
            if (isCli) {
                if (cliCmdName != null && !details.contains("[via CLI:")) {
                    details += String.format(" [via CLI: %s]", cliCmdName);
                }
                if (!action.startsWith("[CLI] ")) {
                    action = "[CLI] " + action;
                }
            }

            AuditLogEntry entry = new AuditLogEntry(username, action, nodeName, details);
            if ("NODE_LAUNCH_FAILURE".equals(baseAction)) {
                entry.setSeverity("CRITICAL"); // Red badge for agent launch failures
            } else if ("NODE_TEMPORARILY_OFFLINE".equals(baseAction) || "NODE_OFFLINE".equals(baseAction)) {
                entry.setSeverity("HIGH"); // Orange badge
            } else {
                entry.setSeverity("LOW"); // Green badge for NODE_ONLINE and other computer events
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
