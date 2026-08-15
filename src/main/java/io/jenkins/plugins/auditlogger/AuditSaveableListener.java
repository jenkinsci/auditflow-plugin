package io.jenkins.plugins.auditlogger;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.kohsuke.stapler.Stapler;

import hudson.Extension;
import hudson.XmlFile;
import hudson.model.Fingerprint;
import hudson.model.Job;
import hudson.model.Run;
import hudson.model.Saveable;
import hudson.model.User;
import hudson.model.listeners.SaveableListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jenkins.model.Jenkins;

/**
 * Configuration change listener: tracks saves to jobs, users, system settings, and credentials.
 * Uses reflection for credential detection to avoid hard dependency on credentials plugin.
 */
@Extension
public class AuditSaveableListener extends SaveableListener {
    private static final Logger LOGGER = Logger.getLogger(AuditSaveableListener.class.getName());
    private static final String SYSTEM_CREDENTIALS_PROVIDER =
            "com.cloudbees.plugins.credentials.SystemCredentialsProvider";
    private static final Set<String> USER_THEME_SAVEABLE_CLASS_NAMES = Set.of(
            "io.jenkins.plugins.thememanager.ThemeUserProperty"
    );

   
    private static final Map<String, Set<String>> credentialCache = new ConcurrentHashMap<>();

    private static final Map<String, Map<String, Integer>> credentialHashCache = new ConcurrentHashMap<>();

    static void primeCredentialCaches() {
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins == null) {
                return;
            }

            ClassLoader loader = jenkins.getPluginManager().uberClassLoader;
            Class<?> providerClass = Class.forName(SYSTEM_CREDENTIALS_PROVIDER, false, loader);
            Method getInstance = providerClass.getMethod("getInstance");
            Object provider = getInstance.invoke(null);
            if (provider instanceof Saveable) {
                primeCredentialSnapshot((Saveable) provider);
            }

            Method getStore = providerClass.getMethod("getStore");
            Object store = getStore.invoke(provider);
            if (store instanceof Saveable) {
                primeCredentialSnapshot((Saveable) store);
            }
        } catch (ClassNotFoundException e) {
            LOGGER.log(Level.FINE, "Credentials plugin not installed; skipping credential cache priming", e);
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.log(Level.FINE, "Failed to prime credential caches", e);
        }
    }

    @Override
    public void onChange(Saveable o, XmlFile file) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null) return;

            if (isCredentialStore(o)) {
                if (config.isEnableCredentialEvents()) {
                    logCredentialChange(o, file);
                }
                return;
            }

            
            if (o instanceof hudson.model.Node) {
                return;
            }

           
            if (isRuntimeBuildSaveable(o)) {
                return;
            }

            if (StartupPhaseManager.isInStartupGracePeriod()) {
                LOGGER.log(Level.FINE, "Suppressing startup-phase config log for: {0}",
                        o.getClass().getSimpleName());
                return;
            }

            boolean isJob = o instanceof Job;
            boolean isUser = o instanceof User;
            boolean isSystem = !isJob && !isUser;

            if (isJob && !config.isEnableJobConfigEvents()) return;
            if (isSystem && !config.isEnableSystemConfigEvents()) return;

            // Suppress minor user-preference property saves that pollute global audit trail.
            if (isUserThemePreferenceSave(o)) {
                LOGGER.log(Level.FINE, "Suppressing theme preference save for user property: {0}",
                        o.getClass().getName());
                return;
            }

            String action;
            String target;

            if (isJob) {
                action = "JOB_CONFIG_UPDATED";
                target = ((Job<?, ?>) o).getFullName();
            } else if (isUser) {
                action = "USER_CONFIG_UPDATED";
                target = ((User) o).getId();
            } else {
                action = "GLOBAL_CONFIG_UPDATED";
                target = o.getClass().getSimpleName();
            }

            String username = currentUser(target);

            
            if (!isRealUser(username)) {
                LOGGER.log(Level.FINE, "Suppressing non-real user config save: {0}", o.getClass().getSimpleName());
                return;
            }

            String details;
            if (isJob) {
                details = String.format("Job configuration modified: %s by %s", target, username);
            } else if (isUser) {
                details = String.format("User profile updated: %s by %s", target, username);
            } else {
                details = String.format("Global system configuration updated: %s by %s", target, username);
            }

            boolean isCli = false;
            String cliCmdName = null;

            try {
                hudson.cli.CLICommand currentCmd = hudson.cli.CLICommand.getCurrent();
                if (currentCmd != null) {
                    isCli = true;
                    cliCmdName = currentCmd.getName();
                }
            } catch (Throwable ignored) {}

            if (!isCli) {
                AsyncActionTracker.CliAction actionObj = AsyncActionTracker.getInstance().resolveAction(target, action, System.currentTimeMillis());
                if (actionObj != null && (username == null || actionObj.username.equals(username))) {
                    isCli = true;
                    cliCmdName = actionObj.command;
                }
            }

            if (isCli) {
                if (cliCmdName != null && !details.contains("[via CLI:")) {
                    details += String.format(" [via CLI: %s]", cliCmdName);
                }
                action = "[CLI] " + action;
            }

            
            String duplicateKey = action + ":" + target;
            if (StartupPhaseManager.wasRecentlyLogged(duplicateKey)) {
                LOGGER.log(Level.FINE, "Skipping duplicate save log for: {0}", duplicateKey);
                return;
            }
            StartupPhaseManager.markAsLogged(duplicateKey);

            AuditLogEntry entry = new AuditLogEntry(username, action, target, details);
            if (isSystem) {
                entry.setSeverity("MEDIUM"); // Amber badge for system configuration updates
            }
            AuditLogStorage.getInstance().addEntry(entry);
            LOGGER.log(Level.INFO, "{0}: target={1} by user={2}", new Object[]{action, target, username});
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error recording saveable change", e);
        }
    }

    private static boolean isRuntimeBuildSaveable(Saveable o) {
        if (o == null) return false;
        if (o instanceof Run || o instanceof Fingerprint) {
            return true;
        }
        String className = o.getClass().getName();
        return className.contains("WorkflowRun")
                || className.contains("MatrixRun")
                || className.contains("Fingerprint")
                || className.contains("FlowNode")
                || className.contains("PipelineTest")
                || className.contains("Run$")
                || className.contains("Action");
    }

    static boolean shouldSuppressThemeUserPreferenceLog(String className, boolean hasRequest, String requestUri, Set<?> paramKeys) {
        if ("io.jenkins.plugins.thememanager.ThemeUserProperty".equals(className)) {
            return true;
        }
        if (hasRequest && requestUri != null && requestUri.contains("/theme/set")) {
            return true;
        }
        return false;
    }

    static boolean shouldSuppressRequestScopedSystemConfigSave(boolean isSystem, String requestUri) {
        if (!isSystem || requestUri == null) return false;
        return requestUri.endsWith("/configure") || requestUri.contains("/configure");
    }

    private static boolean isUserThemePreferenceSave(Saveable o) {
        if (o == null) return false;
        String className = o.getClass().getName();
        return USER_THEME_SAVEABLE_CLASS_NAMES.contains(className);
    }

    private static boolean isCredentialStore(Saveable o) {
        if (o == null) return false;
        String className = o.getClass().getName();
        return className.contains("CredentialsStore")
                || className.contains("CredentialsProvider")
                || className.contains("SystemCredentialsProvider")
                || className.contains("UserCredentialsProvider");
    }

    private void logCredentialChange(Saveable o, XmlFile file) {
        try {
            String storeName = o.getClass().getSimpleName();
            String username = currentUser(storeName);

            // Extract set of all credential IDs in this store currently
            Set<String> currentIds = extractCredentialIdSet(o);
            // Extract map of credential ID → content hash
            Map<String, Integer> currentHashes = extractCredentialHashes(o);

            Set<String> previousIds = credentialCache.get(storeName);
            Map<String, Integer> previousHashes = credentialHashCache.get(storeName);

            // Update caches FIRST for next check
            credentialCache.put(storeName, currentIds);
            credentialHashCache.put(storeName, currentHashes);

            if (previousIds == null) {
                // First time we see this store — snapshot only, don't log (likely startup)
                LOGGER.log(Level.FINE, "Credential cache initialized for {0}: {1} credentials",
                        new Object[]{storeName, currentIds.size()});
                return;
            }

            // Detect added credentials
            Set<String> added = new HashSet<>(currentIds);
            added.removeAll(previousIds);
            for (String id : added) {
                String actionName = "CREDENTIAL_CREATED";
                String details = String.format("Credential created: %s by %s", id, username);
                AsyncActionTracker.CliAction cliAction = AsyncActionTracker.getInstance().resolveAction(id, System.currentTimeMillis());
                if (cliAction != null && cliAction.username.equals(username)) {
                    details += String.format(" [via CLI: %s]", cliAction.command);
                    actionName = "[CLI] " + actionName;
                }
                AuditLogEntry entry = new AuditLogEntry(username, actionName,
                        id, details);
                entry.setSeverity("INFO"); // Blue badge for creation
                AuditLogStorage.getInstance().addEntry(entry);
                LOGGER.log(Level.INFO, "{0}: id={1} by user={2}",
                        new Object[]{actionName, id, username});
            }

            // Detect removed credentials
            Set<String> removed = new HashSet<>(previousIds);
            removed.removeAll(currentIds);
            for (String id : removed) {
                String actionName = "CREDENTIAL_DELETED";
                String details = String.format("Credential deleted: %s by %s", id, username);
                AsyncActionTracker.CliAction cliAction = AsyncActionTracker.getInstance().resolveAction(id, System.currentTimeMillis());
                if (cliAction != null && cliAction.username.equals(username)) {
                    details += String.format(" [via CLI: %s]", cliAction.command);
                    actionName = "[CLI] " + actionName;
                }
                AuditLogEntry entry = new AuditLogEntry(username, actionName,
                        id, details);
                entry.setSeverity("HIGH"); // Dark Orange badge for deletion
                AuditLogStorage.getInstance().addEntry(entry);
                LOGGER.log(Level.INFO, "{0}: id={1} by user={2}",
                        new Object[]{actionName, id, username});
            }

            // If no adds/removes but store was saved, credentials were modified.
            // Try to identify which specific credential was updated by comparing hashes.
            if (added.isEmpty() && removed.isEmpty()) {
                Set<String> changedCreds = detectModifiedCredentials(currentHashes, previousHashes);
                if (changedCreds.isEmpty() && !previousHashes.isEmpty()) {
                    // Hashes matched — no actual content change detected, skip logging
                    LOGGER.log(Level.FINE, "Credential store saved but no content changes detected");
                    return;
                }
                if (changedCreds.isEmpty()) {
                    // No previous hashes to compare — fallback to log all
                    changedCreds = currentIds;
                }
                for (String credId : changedCreds) {
                    String actionName = "CREDENTIAL_UPDATED";
                    String details = String.format("Credential updated: %s by %s", credId, username);
                    AsyncActionTracker.CliAction cliAction = AsyncActionTracker.getInstance().resolveAction(credId, System.currentTimeMillis());
                    if (cliAction != null && cliAction.username.equals(username)) {
                        details += String.format(" [via CLI: %s]", cliAction.command);
                        actionName = "[CLI] " + actionName;
                    }
                    AuditLogEntry entry = new AuditLogEntry(username, actionName,
                            credId, details);
                    entry.setSeverity("MEDIUM"); // Amber badge for updates
                    AuditLogStorage.getInstance().addEntry(entry);
                    LOGGER.log(Level.INFO, "{0}: id={1} by user={2}",
                            new Object[]{actionName, credId, username});
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error recording credential change", e);
        }
    }

    private static Set<String> extractCredentialIdSet(Saveable o) {
        Set<String> ids = new HashSet<>();
        try {
            boolean found = false;
            for (Method m : o.getClass().getMethods()) {
                if ("getDomainCredentialsMap".equals(m.getName()) && m.getParameterCount() == 0) {
                    Object domainMap = m.invoke(o);
                    if (domainMap instanceof Iterable) {
                        for (Object domainCreds : (Iterable<?>) domainMap) {
                            extractCredentialIdsFromContainer(domainCreds, ids);
                        }
                    } else if (domainMap instanceof java.util.Map) {
                        for (Object value : ((java.util.Map<?, ?>) domainMap).values()) {
                            if (value instanceof Iterable) {
                                for (Object cred : (Iterable<?>) value) {
                                    String id = extractCredentialId(cred);
                                    if (id != null) ids.add(id);
                                }
                            }
                        }
                    }
                    found = true;
                    break;
                }
            }

            if (!found) {
                for (Method m : o.getClass().getMethods()) {
                    if ("getCredentials".equals(m.getName()) && m.getParameterCount() == 0) {
                        Object creds = m.invoke(o);
                        if (creds instanceof Iterable) {
                            for (Object cred : (Iterable<?>) creds) {
                                String id = extractCredentialId(cred);
                                if (id != null) ids.add(id);
                            }
                        }
                        break;
                    }
                }
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.log(Level.FINE, "Error extracting credential IDs via reflection", e);
        }
        return ids;
    }

    private static void extractCredentialIdsFromContainer(Object domainCreds, Set<String> ids) {
        if (domainCreds == null) return;
        try {
            for (Method m : domainCreds.getClass().getMethods()) {
                if ("getCredentials".equals(m.getName()) && m.getParameterCount() == 0) {
                    Object creds = m.invoke(domainCreds);
                    if (creds instanceof Iterable) {
                        for (Object cred : (Iterable<?>) creds) {
                            String id = extractCredentialId(cred);
                            if (id != null) ids.add(id);
                        }
                    }
                    break;
                }
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
    }

    private static String extractCredentialId(Object cred) {
        if (cred == null) return null;
        try {
            Method getId = cred.getClass().getMethod("getId");
            Object id = getId.invoke(cred);
            return id != null ? id.toString() : null;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }

    private static Map<String, Integer> extractCredentialHashes(Saveable o) {
        Map<String, Integer> hashes = new ConcurrentHashMap<>();
        try {
            Set<String> ids = extractCredentialIdSet(o);
            for (String id : ids) {
                Object credObj = findCredentialObjectById(o, id);
                if (credObj != null) {
                    hashes.put(id, computeCredentialHash(credObj));
                }
            }
        } catch (RuntimeException e) {
            LOGGER.log(Level.FINE, "Error computing credential hashes", e);
        }
        return hashes;
    }

    private static Object findCredentialObjectById(Saveable o, String targetId) {
        try {
            for (Method m : o.getClass().getMethods()) {
                if ("getDomainCredentialsMap".equals(m.getName()) && m.getParameterCount() == 0) {
                    Object domainMap = m.invoke(o);
                    if (domainMap instanceof Iterable) {
                        for (Object domainCreds : (Iterable<?>) domainMap) {
                            Object found = findCredInContainer(domainCreds, targetId);
                            if (found != null) return found;
                        }
                    }
                }
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
        return null;
    }

    private static Object findCredInContainer(Object domainCreds, String targetId) {
        if (domainCreds == null) return null;
        try {
            for (Method m : domainCreds.getClass().getMethods()) {
                if ("getCredentials".equals(m.getName()) && m.getParameterCount() == 0) {
                    Object creds = m.invoke(domainCreds);
                    if (creds instanceof Iterable) {
                        for (Object cred : (Iterable<?>) creds) {
                            String id = extractCredentialId(cred);
                            if (targetId.equals(id)) return cred;
                        }
                    }
                }
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
        return null;
    }

    private static int computeCredentialHash(Object cred) {
        if (cred == null) return 0;
        int result = 17;
        try {
            for (Method m : cred.getClass().getMethods()) {
                String name = m.getName();
                if ((name.startsWith("get") || name.startsWith("is"))
                        && m.getParameterCount() == 0
                        && !name.equals("getClass")
                        && !name.equals("getDescriptor")) {
                    try {
                        Object val = m.invoke(cred);
                        result = 31 * result + (val != null ? val.hashCode() : 0);
                    } catch (ReflectiveOperationException | RuntimeException ignored) {}
                }
            }
        } catch (RuntimeException ignored) {}
        return result;
    }

    static void primeCredentialSnapshot(Saveable o) {
        if (o == null) return;
        try {
            String storeName = o.getClass().getSimpleName();
            Set<String> ids = extractCredentialIdSet(o);
            Map<String, Integer> hashes = extractCredentialHashes(o);
            credentialCache.put(storeName, ids);
            credentialHashCache.put(storeName, hashes);
            LOGGER.log(Level.INFO, "Primed credential cache for {0}: {1} entries",
                    new Object[]{storeName, ids.size()});
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Failed to prime credential snapshot for " + o.getClass().getSimpleName(), e);
        }
    }

    private static Set<String> detectModifiedCredentials(Map<String, Integer> currentHashes,
                                                         Map<String, Integer> previousHashes) {
        Set<String> modified = new HashSet<>();
        if (previousHashes == null) return modified;

        for (Map.Entry<String, Integer> entry : currentHashes.entrySet()) {
            String id = entry.getKey();
            Integer currentHash = entry.getValue();
            Integer prevHash = previousHashes.get(id);
            if (prevHash != null && !prevHash.equals(currentHash)) {
                modified.add(id);
            }
        }
        return modified;
    }

    private static String currentUser(String affectedObject) {
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
                if (request.getSession(false) != null) {
                    String sessionUser = extractUserFromSession(request.getSession(false));
                    if (isRealUser(sessionUser)) {
                        return sessionUser;
                    }
                }
                String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Basic ")) {
                    String decoded = new String(java.util.Base64.getDecoder().decode(authHeader.substring(6)), java.nio.charset.StandardCharsets.UTF_8);
                    String username = decoded.contains(":") ? decoded.substring(0, decoded.indexOf(':')) : decoded;
                    if (isRealUser(username)) return username;
                }
                if (isRealUser(request.getRemoteUser())) {
                    return request.getRemoteUser();
                }
                Principal principal = request.getUserPrincipal();
                if (principal != null && isRealUser(principal.getName())) {
                    return principal.getName();
                }
            }
        } catch (RuntimeException ignored) {}

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
        } catch (RuntimeException ignored) {}

        // 4. Try Jenkins User.current()
        try {
            User user = User.current();
            if (user != null && isRealUser(user.getId())) {
                return user.getId();
            }
        } catch (RuntimeException ignored) {}

        // 5. Try Spring SecurityContext
        try {
            var authentication = org.springframework.security.core.context.SecurityContextHolder
                    .getContext().getAuthentication();
            if (authentication != null && isRealUser(authentication.getName())) {
                return authentication.getName();
            }
        } catch (RuntimeException ignored) {}

        // 6. Last resort: check if a recent CLI command correlates with this background event
        if (affectedObject != null) {
            String cliUser = AsyncActionTracker.getInstance().resolveUser(affectedObject, System.currentTimeMillis());
            if (cliUser != null) {
                LOGGER.log(Level.FINE, "currentUser from AsyncActionTracker for {0}: {1}", new Object[]{affectedObject, cliUser});
                return cliUser;
            }
        }

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
