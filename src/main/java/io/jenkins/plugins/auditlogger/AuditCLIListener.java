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

            // Only register the action in AsyncActionTracker so that domain listeners 
            // (like AuditRunListener, AuditItemListener) can pick it up and prefix 
            // their own domain events with [CLI]. 
            // We no longer log a standalone CLI_EXECUTION event to reduce noise.
            AsyncActionTracker.getInstance().register(username, command, context.getArgs(), System.currentTimeMillis());
            LOGGER.log(Level.FINE, "Registered CLI execution for command: {0}", command);
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

}
