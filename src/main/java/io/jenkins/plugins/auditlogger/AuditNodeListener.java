package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.Node;
import hudson.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.kohsuke.stapler.Stapler;

import java.lang.reflect.Method;
import java.security.Principal;
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
        log("NODE_UPDATED", newNode,
                "Node configuration updated: %s by %s");
    }

    @Override
    public void onDeleted(Node node) {
        log("NODE_DELETED", node,
                "Node deleted: %s by %s");
    }

    private void log(String action, Node node, String detailsTemplate) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableNodeEvents()) {
                return;
            }

            String username = currentUser();
            String nodeName = nodeName(node);

            // Suppress SYSTEM-initiated node events (startup node loading, automated background tasks)
            // — consistent with AuditItemListener and AuditSaveableListener compliance filtering.
            if (!isRealUser(username)) {
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

            String details = "NODE_CREATED".equals(action)
                    ? String.format(detailsTemplate, nodeName, node.getClass().getSimpleName(), username)
                    : String.format(detailsTemplate, nodeName, username);
            AuditLogEntry entry = new AuditLogEntry(username, action, nodeName, details);
            if ("NODE_UPDATED".equals(action)) {
                entry.setSeverity("MEDIUM");
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

        // 2. Try session-based Spring Security context or request user
        try {
            HttpServletRequest request = RequestHolder.get();
            if (request != null) {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    Object context = session.getAttribute("SPRING_SECURITY_CONTEXT");
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
                }
                if (isRealUser(request.getRemoteUser())) {
                    return request.getRemoteUser();
                }
                Principal principal = request.getUserPrincipal();
                if (principal != null && isRealUser(principal.getName())) {
                    return principal.getName();
                }
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Continue through the remaining Jenkins user-resolution mechanisms.
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
        var authentication = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication();
        return authentication != null && isRealUser(authentication.getName())
                ? authentication.getName()
                : "SYSTEM";
    }

    private static boolean isRealUser(String username) {
        return username != null
                && !username.isEmpty()
                && !"SYSTEM".equalsIgnoreCase(username)
                && !"anonymous".equalsIgnoreCase(username)
                && !"anonymousUser".equalsIgnoreCase(username);
    }
}
