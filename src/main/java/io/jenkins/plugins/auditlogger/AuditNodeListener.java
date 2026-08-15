package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.Node;
import hudson.model.Slave;
import hudson.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.kohsuke.stapler.Stapler;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.NodeListener;

/** Records administrator-initiated Jenkins agent lifecycle changes. */
@Extension
public class AuditNodeListener extends NodeListener {
    private static final Logger LOGGER = Logger.getLogger(AuditNodeListener.class.getName());

    @Override
    public void onCreated(Node node) {
        log("NODE_CREATED", node,
                "Node created: %s (type: %s) by %s");
    }

    @Override
    public void onUpdated(Node oldNode, Node newNode) {
        // Suppress NODE_UPDATED if this update is triggered as part of an offline/online status toggle
        if (isStatusToggleRequest()) {
            LOGGER.log(Level.FINE, "Suppressing NODE_UPDATED because status toggle request is active");
            return;
        }
        logUpdate(oldNode, newNode);
    }

    @Override
    public void onDeleted(Node node) {
        log("NODE_DELETED", node,
                "Node deleted: %s by %s");
    }

    private static boolean isStatusToggleRequest() {
        for (StackTraceElement element : Thread.currentThread().getStackTrace()) {
            String method = element.getMethodName();
            if ("setTemporarilyOffline".equals(method)
                    || "toggleOffline".equals(method)
                    || "doToggleOffline".equals(method)
                    || "changeOfflineCause".equals(method)
                    || "doChangeOfflineCause".equals(method)
                    || "bringOnline".equals(method)
                    || "doBringOnline".equals(method)) {
                return true;
            }
        }
        return false;
    }

    private void logUpdate(Node oldNode, Node newNode) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableNodeEvents()) {
                return;
            }

            String username = currentUser();
            String nodeName = nodeName(newNode);

            boolean hasRequest = RequestHolder.get() != null || Stapler.getCurrentRequest2() != null;
            if (!isRealUser(username) && (!hasRequest || StartupPhaseManager.isInStartupGracePeriod())) {
                LOGGER.log(Level.FINE, "Suppressing non-real user node update event on {0}", nodeName);
                return;
            }

            String duplicateKey = "NODE:NODE_UPDATED:" + nodeName;
            if (StartupPhaseManager.wasRecentlyLogged(duplicateKey)) {
                LOGGER.log(Level.FINE, "Skipping duplicate node update log for: {0}", duplicateKey);
                return;
            }
            StartupPhaseManager.markAsLogged(duplicateKey);
            StartupPhaseManager.markAsLogged("NODE_UPDATED_RECENT:" + nodeName);

            String details = formatNodeUpdateDetails(oldNode, newNode, username);
            String actionName = "NODE_UPDATED";
            AsyncActionTracker.CliAction actionObj = AsyncActionTracker.getInstance().resolveAction(nodeName, actionName, System.currentTimeMillis());
            if (actionObj != null && (username == null || actionObj.username.equals(username))) {
                if (!details.contains("[via CLI:")) {
                    details += String.format(" [via CLI: %s]", actionObj.command);
                }
                actionName = "[CLI] " + actionName;
            }
            AuditLogEntry entry = new AuditLogEntry(username, actionName, nodeName, details);
            entry.setSeverity("MEDIUM"); // Amber badge for NODE_UPDATED configuration changes
            AuditLogStorage.getInstance().addEntry(entry);
            LOGGER.log(Level.INFO, "Node Event: NODE_UPDATED on {0} by {1}", new Object[]{nodeName, username});
        } catch (RuntimeException e) {
            LOGGER.log(Level.FINE, "Error recording node update event", e);
        }
    }

    private static String formatNodeUpdateDetails(Node oldNode, Node newNode, String username) {
        String nodeName = nodeName(newNode);
        if (oldNode == null) {
            return String.format("Node configuration updated: %s by %s", nodeName, username);
        }
        List<String> changes = new ArrayList<>();
        if (!Objects.equals(oldNode.getNodeDescription(), newNode.getNodeDescription())) {
            changes.add("description");
        }
        if (oldNode.getNumExecutors() != newNode.getNumExecutors()) {
            changes.add(String.format("executors (%d -> %d)", oldNode.getNumExecutors(), newNode.getNumExecutors()));
        }
        if (oldNode instanceof Slave oldSlave && newNode instanceof Slave newSlave) {
            if (!Objects.equals(oldSlave.getRemoteFS(), newSlave.getRemoteFS())) {
                changes.add("remote FS");
            }
        }
        if (!Objects.equals(oldNode.getLabelString(), newNode.getLabelString())) {
            changes.add("labels");
        }
        if (!Objects.equals(oldNode.getMode(), newNode.getMode())) {
            changes.add("usage mode");
        }

        if (changes.isEmpty()) {
            return String.format("Node configuration updated: %s by %s", nodeName, username);
        } else {
            return String.format("Node configuration updated: %s (%s) by %s", nodeName, String.join(", ", changes), username);
        }
    }

    private void log(String action, Node node, String detailsTemplate) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableNodeEvents()) {
                return;
            }

            String username = currentUser();
            String nodeName = nodeName(node);

            boolean hasRequest = RequestHolder.get() != null || Stapler.getCurrentRequest2() != null;
            if (!isRealUser(username) && (!hasRequest || StartupPhaseManager.isInStartupGracePeriod())) {
                LOGGER.log(Level.FINE, "Suppressing non-real user node event: {0} on {1}",
                        new Object[]{action, nodeName});
                return;
            }

            String duplicateKey = "NODE:" + action + ":" + nodeName;
            if (StartupPhaseManager.wasRecentlyLogged(duplicateKey)) {
                LOGGER.log(Level.FINE, "Skipping duplicate node log for: {0}", duplicateKey);
                return;
            }
            StartupPhaseManager.markAsLogged(duplicateKey);

            String baseAction = action;
            String details = "NODE_CREATED".equals(baseAction)
                    ? String.format(detailsTemplate, nodeName, node.getClass().getSimpleName(), username)
                    : String.format(detailsTemplate, nodeName, username);

            AsyncActionTracker.CliAction actionObj = AsyncActionTracker.getInstance().resolveAction(nodeName, baseAction, System.currentTimeMillis());
            if (actionObj != null && (username == null || actionObj.username.equals(username))) {
                if (!details.contains("[via CLI:")) {
                    details += String.format(" [via CLI: %s]", actionObj.command);
                }
                action = "[CLI] " + action;
            }

            AuditLogEntry entry = new AuditLogEntry(username, action, nodeName, details);
            if ("NODE_CREATED".equals(baseAction)) {
                entry.setSeverity("INFO"); // Blue badge for NODE_CREATED
            } else if ("NODE_DELETED".equals(baseAction)) {
                entry.setSeverity("HIGH"); // Dark Orange badge for NODE_DELETED
            }
            AuditLogStorage.getInstance().addEntry(entry);
        } catch (RuntimeException e) {
            LOGGER.log(Level.FINE, "Error recording node event: " + action, e);
        }
    }

    private static String nodeName(Node node) {
        String name = node != null ? node.getNodeName() : null;
        return name == null || name.isBlank() ? "built-in" : name;
    }

    private static String currentUser() {
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

        // 2. Try session-based Spring Security / Acegi context or request user
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
        } catch (RuntimeException ignored) {
            // No request is expected for some programmatic node changes.
        }

        // 4. Try Jenkins User.current()
        try {
            User user = User.current();
            if (user != null && isRealUser(user.getId())) {
                return user.getId();
            }
        } catch (RuntimeException ignored) {
            // Fall through to the Spring Security context.
        }

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
