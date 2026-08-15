package io.jenkins.plugins.auditlogger;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Tracks recent CLI executions to correlate background SYSTEM actions back to the initiating user.
 * Keeps entries for a short time window (TTL) and resolves them via exact or partial arg matching,
 * prioritizing correctness over coverage (ambiguous matches return null).
 */
public class AsyncActionTracker {
    private static final Logger LOGGER = Logger.getLogger(AsyncActionTracker.class.getName());
    private static final AsyncActionTracker INSTANCE = new AsyncActionTracker();
    private static final long TTL_MS = 10000; // 10 seconds

    private final ConcurrentLinkedQueue<CliAction> recentActions = new ConcurrentLinkedQueue<>();

    private AsyncActionTracker() {}

    public static AsyncActionTracker getInstance() { return INSTANCE; }

    public void register(String username, String command, List<String> args, long timestamp) {
        cleanExpired(System.currentTimeMillis());
        recentActions.add(new CliAction(username, command, args, timestamp));
        LOGGER.log(Level.FINE, "Registered CLI action for {0}: {1}", new Object[]{username, command});
    }

    public CliAction resolveAction(String affectedObject, long now) {
        return resolveAction(affectedObject, null, now);
    }

    public CliAction resolveAction(String affectedObject, String currentActionName, long now) {
        cleanExpired(now);
        CliAction matchedAction = null;

        for (CliAction action : recentActions) {
            if (action.timestamp > now - TTL_MS) {
                if (matches(action, affectedObject) && isCommandCompatible(action.command, currentActionName)) {
                    if (matchedAction != null && !matchedAction.username.equals(action.username)) {
                        LOGGER.log(Level.FINE, "Ambiguous match for {0}, returning null", affectedObject);
                        return null; // Ambiguous match -> give up
                    }
                    matchedAction = action;
                }
            }
        }
        return matchedAction;
    }

    private static boolean isCommandCompatible(String cliCmd, String domainAction) {
        if (cliCmd == null || domainAction == null) return true;
        String cmd = cliCmd.toLowerCase(java.util.Locale.ENGLISH);
        String act = domainAction.toUpperCase(java.util.Locale.ENGLISH);

        if (cmd.equals("groovy") || cmd.equals("groovysh")) return true;

        if (act.contains("DELETE")) {
            return cmd.contains("delete") || cmd.contains("remove") || cmd.contains("rm") || cmd.contains("uninstall");
        }
        if (act.contains("CREATE")) {
            return cmd.contains("create") || cmd.contains("add") || cmd.contains("copy") || cmd.contains("install");
        }
        if (act.contains("UPDATE") || act.contains("CONFIG") || act.contains("RENAMED") || act.contains("MOVED")) {
            return cmd.contains("update") || cmd.contains("configure") || cmd.contains("enable") || cmd.contains("disable") || cmd.contains("rename") || cmd.contains("move");
        }
        if (act.contains("BUILD") || act.contains("PIPELINE")) {
            return cmd.contains("build");
        }
        if (act.contains("OFFLINE")) {
            return cmd.contains("offline") || cmd.contains("disconnect");
        }
        if (act.contains("ONLINE")) {
            return cmd.contains("online") || cmd.contains("connect");
        }

        return true;
    }

    public String resolveUser(String affectedObject, long now) {
        CliAction action = resolveAction(affectedObject, now);
        return action != null ? action.username : null;
    }

    private boolean matches(CliAction action, String affectedObject) {
        if (affectedObject == null) return false;
        String lowerAffected = affectedObject.toLowerCase(java.util.Locale.ENGLISH);
        for (String arg : action.args) {
            if (arg != null && !arg.isEmpty() && lowerAffected.contains(arg.toLowerCase(java.util.Locale.ENGLISH))) {
                return true;
            }
        }
        return false;
    }

    private void cleanExpired(long now) {
        recentActions.removeIf(action -> action.timestamp <= now - TTL_MS);
    }

    public static class CliAction {
        public final String username;
        public final String command;
        public final List<String> args;
        public final long timestamp;

        CliAction(String username, String command, List<String> args, long timestamp) {
            this.username = username;
            this.command = command;
            this.args = args;
            this.timestamp = timestamp;
        }
    }
}
