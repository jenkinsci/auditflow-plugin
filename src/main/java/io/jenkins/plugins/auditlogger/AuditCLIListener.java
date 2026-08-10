package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import jenkins.cli.listeners.CLIContext;
import jenkins.cli.listeners.CLIListener;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Audits CLI execution from Jenkins' core CLIListener callback.
 */
@Extension
public class AuditCLIListener implements CLIListener {
    private static final Logger LOGGER = Logger.getLogger(AuditCLIListener.class.getName());
    static final String CLI_EXECUTION_ACTION = "CLI_EXECUTION";

    @Override
    public void onCompleted(CLIContext context, int exitCode) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null || !config.isEnableSystemConfigEvents()) {
                return;
            }

            String username = resolveCurrentUser(context);

            String command = context.getCommand();
            String details = "CLI Command: " + command + " | Exit Code: " + exitCode +
                    (context.getArgs() != null && !context.getArgs().isEmpty() ? " | Args: " + context.getArgs() : "");

            String target = "CLI: " + command;
            AuditLogEntry entry = new AuditLogEntry(username, CLI_EXECUTION_ACTION, target, details);
            entry.setSeverity(determineSeverity(command, exitCode));

            AuditLogStorage.getInstance().addEntry(entry);

            LOGGER.log(Level.INFO, "CLI_EXECUTION: target={0}, exitCode={1}, user={2}",
                    new Object[]{target, exitCode, username});

            
            AsyncActionTracker.getInstance().register(username, command, context.getArgs(), System.currentTimeMillis());
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error recording CLI execution", e);
        }
    }

    private String resolveCurrentUser(CLIContext context) {
        var auth = context.getAuth();
        if (auth != null) {
            String name = auth.getName();
            if (name != null && !name.isEmpty() && !"anonymousUser".equals(name) && !"anonymous".equalsIgnoreCase(name)) {
                return name;
            }
        }
        return "SYSTEM";
    }

    private String determineSeverity(String command, int exitCode) {
        if (exitCode != 0) {
            return "MEDIUM";
        }
        
        if (command == null) {
            return "LOW";
        }
        
        switch (command.toLowerCase()) {
            case "delete-job":
            case "delete-node":
            case "delete-builds":
            case "delete-credentials":
            case "delete-view":
            case "install-plugin":
            case "uninstall-plugin":
            case "restart":
            case "safe-restart":
            case "quiet-down":
            case "cancel-quiet-down":
            case "groovy":
            case "groovysh":
                return "HIGH";
                
            case "build":
            case "create-job":
            case "create-node":
            case "create-view":
            case "create-credentials":
            case "update-job":
            case "update-node":
            case "update-view":
            case "update-credentials":
            case "reload-configuration":
            case "enable-job":
            case "disable-job":
            case "offline-node":
            case "online-node":
            case "clear-queue":
            case "set-external-build-result":
            case "keep-build":
                return "MEDIUM";
                
            default:
                return "LOW";
        }
    }
}
