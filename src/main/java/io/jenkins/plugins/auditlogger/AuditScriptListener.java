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

            String target = resolveTarget(feature);
            String details = String.format(
                    "Script execution: %s | Feature: %s | Context: %s | Correlation: %s | User: %s",
                    preview(script),
                    describeObject(feature),
                    describeObject(context),
                    describeCorrelation(correlationId),
                    username
            );

            AuditLogEntry entry = new AuditLogEntry(username, "SCRIPT_CONSOLE_ACCESS", target, details);
            entry.setSeverity("CRITICAL");
            AuditLogStorage.getInstance().addEntry(entry);

            LOGGER.log(Level.INFO, "SCRIPT_CONSOLE_ACCESS: target={0}, feature={1}, user={2}",
                    new Object[]{target, describeObject(feature), username});
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error recording script execution", e);
        }
    }

    @Override
    public void onScriptOutput(String output, Object feature, Object context, String correlationId, User user) {
        // The execution callback records a single audit event per script run.
    }

    private static String resolveTarget(Object feature) {
        String featureName = describeObject(feature);
        if (featureName.contains("RemotingDiagnostics")) {
            return "ScriptConsole";
        }
        if (featureName.contains("GroovyCommand")) {
            return "GroovyCLI";
        }
        return "GroovyExecution";
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
