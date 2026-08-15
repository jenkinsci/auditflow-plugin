package io.jenkins.plugins.auditlogger;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.kohsuke.stapler.Stapler;

import hudson.Extension;
import hudson.model.Item;
import hudson.model.User;
import hudson.model.listeners.ItemListener;

/**
 * Job lifecycle listener it created, deleted, updated, renamed, copied, moved.
 */
@Extension
public class AuditItemListener extends ItemListener {
    private static final Logger LOGGER = Logger.getLogger(AuditItemListener.class.getName());

    @Override
    public void onCreated(Item item) {
        String target = item.getFullName();
        String user = currentUser(target);
        String details = String.format("Job created: %s (type: %s) by %s", target, item.getClass().getSimpleName(), user);
        checkCliAndLog("JOB_CREATED", target, details, user);
    }

    @Override
    public void onDeleted(Item item) {
        String target = item.getFullName();
        String user = currentUser(target);
        String details = String.format("Job deleted: %s by %s", target, user);
        checkCliAndLog("JOB_DELETED", target, details, user);
    }

    @Override
    public void onRenamed(Item item, String oldName, String newName) {
        String target = item.getFullName();
        String user = currentUser(target);
        String details = String.format("Job renamed from '%s' to '%s' by %s", oldName, newName, user);
        checkCliAndLog("JOB_RENAMED", target, details, user);
    }

    @Override
    public void onCopied(Item src, Item copy) {
        String target = copy.getFullName();
        String user = currentUser(target);
        String details = String.format("Job copied from '%s' by %s", src.getFullName(), user);
        checkCliAndLog("JOB_COPIED", target, details, user);
    }

    @Override
    public void onLocationChanged(Item item, String oldFullName, String newFullName) {
        String user = currentUser(newFullName);
        String details = String.format("Job moved from '%s' by %s", oldFullName, user);
        checkCliAndLog("JOB_MOVED", newFullName, details, user);
    }

    private void checkCliAndLog(String actionName, String target, String details, String user) {
        boolean isCli = false;
        String cliCmdName = null;
        try {
            hudson.cli.CLICommand cliCmd = hudson.cli.CLICommand.getCLICommand();
            if (cliCmd != null) {
                isCli = true;
                cliCmdName = cliCmd.getName();
            }
        } catch (Throwable ignored) {}

        if (!isCli) {
            AsyncActionTracker.CliAction action = AsyncActionTracker.getInstance().resolveAction(target, System.currentTimeMillis());
            if (action != null && (user == null || action.username.equals(user))) {
                isCli = true;
                cliCmdName = action.command;
            }
        }

        if (isCli) {
            if (cliCmdName != null && !details.contains("[via CLI:")) {
                details += String.format(" [via CLI: %s]", cliCmdName);
            }
            if (!actionName.startsWith("[CLI] ")) {
                actionName = "[CLI] " + actionName;
            }
        }
        log(actionName, target, details, user);
    }

    private void log(String action, String target, String details, String username) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableJobConfigEvents()) return;

            if (StartupPhaseManager.isInStartupGracePeriod()) {
                LOGGER.log(Level.FINE, "Suppressing startup-phase job event: {0} on {1}",
                        new Object[]{action, target});
                return;
            }

           
            if ("SYSTEM".equals(username)) {
                LOGGER.log(Level.FINE, "Suppressing SYSTEM item event: {0} on {1}",
                        new Object[]{action, target});
                return;
            }

            AuditLogStorage.getInstance().addEntry(
                    new AuditLogEntry(username, action, target, details));
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error recording item event: " + action, e);
        }
    }

    private static String currentUser(String affectedObject) {
        
        try {
            jakarta.servlet.http.HttpServletRequest req = RequestHolder.get();
            if (req != null) {
                jakarta.servlet.http.HttpSession session = req.getSession(false);
                if (session != null) {
                    Object ctx = session.getAttribute("SPRING_SECURITY_CONTEXT");
                    if (ctx != null) {
                        java.lang.reflect.Method getAuth = ctx.getClass().getMethod("getAuthentication");
                        Object auth = getAuth.invoke(ctx);
                        if (auth != null) {
                            java.lang.reflect.Method getName = auth.getClass().getMethod("getName");
                            String name = (String) getName.invoke(auth);
                            if (isRealUser(name)) return name;
                        }
                    }
                }
                String remoteUser = req.getRemoteUser();
                if (isRealUser(remoteUser)) return remoteUser;
                java.security.Principal p = req.getUserPrincipal();
                if (p != null && isRealUser(p.getName())) return p.getName();
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
        
        try {
            org.kohsuke.stapler.StaplerRequest2 req = Stapler.getCurrentRequest2();
            if (req != null) {
                String remoteUser = req.getRemoteUser();
                if (isRealUser(remoteUser)) return remoteUser;
                java.security.Principal p = req.getUserPrincipal();
                if (p != null && isRealUser(p.getName())) return p.getName();
            }
        } catch (RuntimeException ignored) {}
       
        try {
            User u = User.current();
            if (u != null && isRealUser(u.getId())) return u.getId();
        } catch (RuntimeException ignored) {}
      
        try {
            org.springframework.security.core.Authentication auth =
                    org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && isRealUser(auth.getName())) {
                return auth.getName();
            }
        } catch (RuntimeException ignored) {}

        
        if (affectedObject != null) {
            String cliUser = AsyncActionTracker.getInstance().resolveUser(affectedObject, System.currentTimeMillis());
            if (cliUser != null) {
                LOGGER.log(Level.FINE, "currentUser from AsyncActionTracker for {0}: {1}", new Object[]{affectedObject, cliUser});
                return cliUser;
            }
        }

        return "SYSTEM";
    }

    private static boolean isRealUser(String name) {
        return name != null && !name.isEmpty()
                && !"SYSTEM".equalsIgnoreCase(name)
                && !"anonymous".equalsIgnoreCase(name)
                && !"anonymousUser".equals(name);
    }
}
