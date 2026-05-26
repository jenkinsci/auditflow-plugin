package io.jenkins.plugins.auditlogger;

import hudson.init.InitMilestone;
import hudson.init.Initializer;
import jenkins.model.Jenkins;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Registers AuditSessionListener with the servlet context.
 * Uses @Initializer instead of implementing ServletContextListener
 * (which doesn't work as a Jenkins @Extension).
 */
public class AuditSessionListenerInitializer {
    private static final Logger LOGGER = Logger.getLogger(AuditSessionListenerInitializer.class.getName());
    private static volatile boolean registered = false;

    @Initializer(after = InitMilestone.STARTED)
    public static void register() {
        if (registered) return;
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins == null) return;
            var ctx = jenkins.getServletContext();
            if (ctx == null) return;
            ctx.addListener(new AuditSessionListener());
            registered = true;
            LOGGER.info("Audit Session Listener registered with servlet context");
        } catch (IllegalStateException | UnsupportedOperationException e) {
            LOGGER.log(Level.FINE, "Session listener registration is not supported by this Jenkins servlet container. " +
                    "Session termination events will not be tracked.", e);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to register Audit Session Listener", e);
        }
    }
}
