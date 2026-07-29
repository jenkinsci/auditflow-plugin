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
            // Node definitions are loaded during startup under SYSTEM. Suppress those
            // without hiding genuine administrator changes made during the grace period.
            if (!isRealUser(username)) {
                return;
            }

            String nodeName = nodeName(node);
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
        String requestUser = RequestHolder.getAuthenticatedUser();
        if (isRealUser(requestUser)) {
            return requestUser;
        }

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

        try {
            var request = Stapler.getCurrentRequest2();
            if (request != null && isRealUser(request.getRemoteUser())) {
                return request.getRemoteUser();
            }
        } catch (RuntimeException ignored) {
            // No request is expected for some programmatic node changes.
        }

        try {
            User user = User.current();
            if (user != null && isRealUser(user.getId())) {
                return user.getId();
            }
        } catch (RuntimeException ignored) {
            // Fall through to the Spring Security context.
        }

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
