package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.User;
import groovy.lang.Binding;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.util.ScriptListener;

/**
 * Audits Groovy execution from Jenkins' core ScriptListener callback.
 */
@Extension
public class AuditScriptListener implements ScriptListener {
    private static final Logger LOGGER = Logger.getLogger(AuditScriptListener.class.getName());
    static final String SCRIPT_CONSOLE_ACCESS_ACTION = "SCRIPT_CONSOLE_ACCESS";
    static final String INIT_SCRIPT_EXECUTED_ACTION = "INIT_SCRIPT_EXECUTED";

    @Override
    public void onScriptExecution(String script, Binding binding, Object feature, Object context,
                                  String correlationId, User user) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null || !config.isEnableSystemConfigEvents()) {
                return;
            }

            String username = resolveCurrentUser(user);
            if (username == null) username = "SYSTEM";

            String action = resolveAction(feature, context);
            boolean initScriptExecution = INIT_SCRIPT_EXECUTED_ACTION.equals(action);
            String target = resolveTarget(feature, action);
            String description = initScriptExecution ? "Init script execution" : "Script execution";
            String details = String.format(
                    "%s: %s | Feature: %s | Context: %s | Correlation: %s | User: %s",
                    description,
                    preview(script),
                    describeObject(feature),
                    describeObject(context),
                    describeCorrelation(correlationId),
                    username
            );

            if ("GroovyCLI".equals(target)) {
                action = "[CLI] " + action;
                details += " [via CLI: groovy]";
            }

            AuditLogEntry entry = new AuditLogEntry(username, action, target, details);
            entry.setSeverity(initScriptExecution ? "LOW" : "CRITICAL");
            AuditLogStorage.getInstance().addEntry(entry);

            LOGGER.log(Level.INFO, "{0}: target={1}, feature={2}, user={3}",
                    new Object[]{action, target, describeObject(feature), username});
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error recording script execution", e);
        }
    }

    @Override
    public void onScriptOutput(String output, Object feature, Object context, String correlationId, User user) {
        // The execution callback records a single audit event per script run.
    }

    static String resolveAction(Object feature, Object context) {
        return isInitScriptExecution(feature, context) ? INIT_SCRIPT_EXECUTED_ACTION : SCRIPT_CONSOLE_ACCESS_ACTION;
    }

    static String resolveTarget(Object feature, String action) {
        if (INIT_SCRIPT_EXECUTED_ACTION.equals(action)) {
            return "InitScript";
        }
        String featureName = describeObject(feature);
        if (featureName.contains("RemotingDiagnostics")) {
            return "ScriptConsole";
        }
        if (featureName.contains("GroovyCommand")) {
            return "GroovyCLI";
        }
        return "GroovyExecution";
    }

    static boolean isInitScriptExecution(Object feature, Object context) {
        String featureName = describeObject(feature);
        if (featureName.contains("GroovyHookScript")) {
            return true;
        }

        String contextName = describeObject(context);
        return contextName.contains("/init.groovy.d/") || contextName.contains("\\init.groovy.d\\");
    }

    private static String resolveCurrentUser(User user) {
        try {
            if (user != null && isRealUser(user.getId())) {
                return user.getId();
            }

            jakarta.servlet.http.HttpServletRequest request = RequestHolder.get();
            if (request != null) {
                String requestUser = (String) request.getAttribute("AUDIT_USER");
                if (isRealUser(requestUser)) {
                    return requestUser;
                }
            }

            User u = User.current();
            if (u != null && isRealUser(u.getId())) {
                return u.getId();
            }

            org.springframework.security.core.Authentication auth =
                    org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && isRealUser(auth.getName())) {
                return auth.getName();
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String preview(String script) {
        if (script == null || script.isEmpty()) {
            return "N/A";
        }
        String collapsed = script.replaceAll("[\\r\\n\\t]+", " ").trim();
        if (collapsed.length() <= 80) {
            return collapsed;
        }
        return collapsed.substring(0, 80) + "...";
    }

    private static String describeObject(Object value) {
        if (value == null) {
            return "N/A";
        }
        if (value instanceof Class<?>) {
            return ((Class<?>) value).getName();
        }
        String text = value.toString();
        if (text == null || text.isBlank()) {
            return value.getClass().getName();
        }
        return text;
    }

    private static String describeCorrelation(String correlationId) {
        if (correlationId == null || correlationId.isBlank()) {
            return "N/A";
        }
        return correlationId;
    }

    private static boolean isRealUser(String name) {
        return name != null && !name.isEmpty()
                && !"anonymousUser".equals(name)
                && !"anonymous".equalsIgnoreCase(name)
                && !"system".equalsIgnoreCase(name);
    }
}
