package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.XmlFile;
import hudson.model.Job;
import hudson.model.Saveable;
import hudson.model.User;
import hudson.model.listeners.SaveableListener;
import jenkins.model.Jenkins;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.kohsuke.stapler.Stapler;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

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

    /** Cache of known credential IDs per store class name, for detecting create/delete. */
    private static final Map<String, Set<String>> credentialCache = new ConcurrentHashMap<>();

    /** Cache of credential hash codes per store, for detecting which credential was modified. */
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

            // Credential store changes are audit-critical — always log, bypass grace period
            if (isCredentialStore(o)) {
                if (config.isEnableCredentialEvents()) {
                    logCredentialChange(o, file);
                }
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

            String objectType = o.getClass().getSimpleName();
            String objectName;
            if (isJob) {
                objectName = ((Job<?, ?>) o).getFullName();
            } else if (isUser) {
                objectName = ((User) o).getId();
                objectType = "User";
            } else {
                objectName = objectType;
            }

            String requestUri = currentRequestUri();
            Set<String> requestParameterNames = currentRequestParameterNames();
            if (shouldSuppressThemeUserPreferenceLog(o.getClass().getName(), isUser, requestUri, requestParameterNames)) {
                LOGGER.log(Level.FINE, "Suppressing user-scoped theme preference save: {0}", objectName);
                return;
            }

            if (shouldSuppressRequestScopedSystemConfigSave(isSystem, requestUri)) {
                LOGGER.log(Level.FINE, "Suppressing request-scoped system config save: {0}", objectName);
                return;
            }

            if (StartupPhaseManager.wasRecentlyLogged(objectName)) {
                LOGGER.log(Level.FINE, "Skipping duplicate config log for: {0}", objectName);
                return;
            }
            StartupPhaseManager.markAsLogged(objectName);

            String username = currentUser();

            // Suppress all SYSTEM-initiated config saves (branch indexing, internal syncs,
            // build rotation, etc.) — not relevant for compliance auditing.
            if ("SYSTEM".equals(username)) {
                LOGGER.log(Level.FINE, "Suppressing SYSTEM config save: {0}", objectName);
                return;
            }

            String action;
            String details;
            if (isJob) {
                action = "JOB_CONFIG_UPDATED";
                details = String.format("Job configuration updated: %s by %s", objectName, username);
            } else if (isUser) {
                action = "USER_CONFIG_UPDATED";
                details = String.format("User configuration updated: %s by %s", objectName, username);
            } else {
                action = "GLOBAL_CONFIG_UPDATED";
                details = String.format("Global configuration updated: %s (%s) by %s", objectName, objectType, username);
            }

            AuditLogStorage.getInstance().addEntry(
                    new AuditLogEntry(username, action, objectName, details));
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error recording config change", e);
        }
    }

    /**
     * Detect credential stores via reflection (avoids hard dependency on credentials plugin).
     * Matches: SystemCredentialsProvider, FolderCredentialsProvider, UserCredentialsProvider, etc.
     */
    private static boolean isCredentialStore(Saveable o) {
        String className = o.getClass().getName().toLowerCase();
        return className.contains("credential");
    }

    private static void primeCredentialSnapshot(Saveable store) {
        String cacheKey = store.getClass().getName();
        Set<String> ids = new HashSet<>(extractCredentialIdSet(store));
        credentialCache.put(cacheKey, ids);
        credentialHashCache.put(cacheKey, buildCredentialHashes(store));
        LOGGER.log(Level.INFO, "Primed credential cache for {0}: {1} entries",
                new Object[]{cacheKey, ids.size()});
    }

    /**
     * Log credential store changes. Compares current credential IDs with a cached snapshot
     * to detect individual credential creates, deletes, and modifications.
     */
    private void logCredentialChange(Saveable o, XmlFile file) {
        try {
            String username = currentUser();
            String storeName = o.getClass().getSimpleName();
            String cacheKey = o.getClass().getName();

            // Get current credential IDs from the store
            Set<String> currentIds = extractCredentialIdSet(o);
            Set<String> previousIds = credentialCache.getOrDefault(cacheKey, null);

            // Build hash snapshot for change detection — save previous before overwriting
            Map<String, Integer> previousHashes = credentialHashCache.getOrDefault(cacheKey, java.util.Collections.emptyMap());
            Map<String, Integer> currentHashes = buildCredentialHashes(o);

            // Update cache for next comparison
            credentialCache.put(cacheKey, new HashSet<>(currentIds));
            credentialHashCache.put(cacheKey, currentHashes);

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
                AuditLogEntry entry = new AuditLogEntry(username, "CREDENTIAL_CREATED",
                        id, String.format("Credential created: %s by %s", id, username));
                entry.setSeverity("CRITICAL");
                AuditLogStorage.getInstance().addEntry(entry);
                LOGGER.log(Level.INFO, "CREDENTIAL_CREATED: id={0} by user={1}",
                        new Object[]{id, username});
            }

            // Detect removed credentials
            Set<String> removed = new HashSet<>(previousIds);
            removed.removeAll(currentIds);
            for (String id : removed) {
                AuditLogEntry entry = new AuditLogEntry(username, "CREDENTIAL_DELETED",
                        id, String.format("Credential deleted: %s by %s", id, username));
                entry.setSeverity("CRITICAL");
                AuditLogStorage.getInstance().addEntry(entry);
                LOGGER.log(Level.INFO, "CREDENTIAL_DELETED: id={0} by user={1}",
                        new Object[]{id, username});
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
                    AuditLogEntry entry = new AuditLogEntry(username, "CREDENTIAL_UPDATED",
                            credId,
                            String.format("Credential updated: %s by %s", credId, username));
                    entry.setSeverity("HIGH");
                    AuditLogStorage.getInstance().addEntry(entry);
                    LOGGER.log(Level.INFO, "CREDENTIAL_UPDATED: id={0} by user={1}",
                            new Object[]{credId, username});
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error recording credential change", e);
        }
    }

    /**
     * Extract credential IDs from a credential store as a Set, via reflection.
     * Handles multiple credential store layouts:
     *   - getCredentials() returning List<Credentials>
     *   - getDomainCredentialsMap() returning List<DomainCredentials> (SystemCredentialsProvider)
     *   - getCredentials(Domain) with parameter
     */
    private static Set<String> extractCredentialIdSet(Saveable o) {
        Set<String> ids = new HashSet<>();
        try {
            // 1. Try getDomainCredentialsMap() — used by SystemCredentialsProvider
            //    Returns List<DomainCredentials>, each has getCredentials() → List<Credentials>
            boolean found = false;
            for (Method m : o.getClass().getMethods()) {
                if ("getDomainCredentialsMap".equals(m.getName()) && m.getParameterCount() == 0) {
                    Object domainMap = m.invoke(o);
                    if (domainMap instanceof Iterable) {
                        for (Object domainCreds : (Iterable<?>) domainMap) {
                            // Each DomainCredentials has getCredentials()
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

            // 2. Try zero-param getCredentials() — some stores expose this directly
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
                        found = true;
                        break;
                    }
                }
            }

            LOGGER.log(Level.FINE, "Extracted {0} credential IDs from {1}",
                    new Object[]{ids.size(), o.getClass().getSimpleName()});
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.log(Level.WARNING, "Could not extract credential IDs from {0}: {1}",
                    new Object[]{o.getClass().getName(), e.getMessage()});
        }
        return ids;
    }

    /**
     * Extract credential IDs from a container object (e.g. DomainCredentials) that has getCredentials().
     */
    private static void extractCredentialIdsFromContainer(Object container, Set<String> ids) {
        try {
            for (Method m : container.getClass().getMethods()) {
                if ("getCredentials".equals(m.getName()) && m.getParameterCount() == 0) {
                    Object creds = m.invoke(container);
                    if (creds instanceof Iterable) {
                        for (Object cred : (Iterable<?>) creds) {
                            String id = extractCredentialId(cred);
                            if (id != null) ids.add(id);
                        }
                    }
                    break;
                }
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.log(Level.FINE, "Could not extract from container: {0}", container.getClass().getName());
        }
    }

    /** Extract the ID from a single credential object via reflection. */
    private static String extractCredentialId(Object cred) {
        try {
            Method getId = cred.getClass().getMethod("getId");
            return (String) getId.invoke(cred);
        } catch (ReflectiveOperationException | RuntimeException e) {
            try {
                // Some credentials use getUsername()
                Method getUsername = cred.getClass().getMethod("getUsername");
                return "user:" + getUsername.invoke(cred);
            } catch (ReflectiveOperationException | RuntimeException ignored) {}
        }
        return null;
    }

    /**
     * Detect which specific credentials were modified by comparing hash codes.
     */
    private Set<String> detectModifiedCredentials(Map<String, Integer> currentHashes, Map<String, Integer> previousHashes) {
        Set<String> changed = new HashSet<>();
        try {
            if (previousHashes.isEmpty()) {
                return changed;
            }
            for (Map.Entry<String, Integer> entry : currentHashes.entrySet()) {
                String id = entry.getKey();
                Integer currentHash = entry.getValue();
                Integer previousHash = previousHashes.get(id);
                if (previousHash != null && !previousHash.equals(currentHash)) {
                    changed.add(id);
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Could not detect modified credential", e);
        }
        return changed;
    }

    /**
     * Build a map of credential ID → content-based hash for detecting modifications.
     */
    private static Map<String, Integer> buildCredentialHashes(Saveable o) {
        Map<String, Integer> hashes = new java.util.HashMap<>();
        try {
            for (Method m : o.getClass().getMethods()) {
                if ("getDomainCredentialsMap".equals(m.getName()) && m.getParameterCount() == 0) {
                    Object domainMap = m.invoke(o);
                    if (domainMap instanceof Iterable) {
                        for (Object domainCreds : (Iterable<?>) domainMap) {
                            buildHashesFromContainer(domainCreds, hashes);
                        }
                    } else if (domainMap instanceof java.util.Map) {
                        // CopyOnWriteMap$Hash: Map<Domain, List<Credentials>>
                        for (Object value : ((java.util.Map<?, ?>) domainMap).values()) {
                            if (value instanceof Iterable) {
                                for (Object cred : (Iterable<?>) value) {
                                    String id = extractCredentialId(cred);
                                    if (id != null) hashes.put(id, computeCredentialHash(cred));
                                }
                            }
                        }
                    }
                    return hashes;
                }
            }
            // Fallback: try getCredentials()
            for (Method m : o.getClass().getMethods()) {
                if ("getCredentials".equals(m.getName()) && m.getParameterCount() == 0) {
                    Object creds = m.invoke(o);
                    if (creds instanceof Iterable) {
                        for (Object cred : (Iterable<?>) creds) {
                            String id = extractCredentialId(cred);
                            if (id != null) hashes.put(id, computeCredentialHash(cred));
                        }
                    }
                    break;
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not build credential hashes: {0}", e.getMessage());
        }
        return hashes;
    }

    private static void buildHashesFromContainer(Object container, Map<String, Integer> hashes) {
        try {
            for (Method m : container.getClass().getMethods()) {
                if ("getCredentials".equals(m.getName()) && m.getParameterCount() == 0) {
                    Object creds = m.invoke(container);
                    if (creds instanceof Iterable) {
                        for (Object cred : (Iterable<?>) creds) {
                            String id = extractCredentialId(cred);
                            if (id != null) hashes.put(id, computeCredentialHash(cred));
                        }
                    }
                    break;
                }
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
    }

    /**
     * Compute a content-based hash for a credential object using its public getter values.
     * Uses only stable identity fields to avoid non-deterministic getters (Descriptor, etc.).
     */
    private static int computeCredentialHash(Object cred) {
        try {
            StringBuilder sb = new StringBuilder();
            // Collect all getter names and sort for determinism
            java.util.List<Method> getters = new java.util.ArrayList<>();
            for (Method m : cred.getClass().getMethods()) {
                if (m.getParameterCount() == 0 && m.getDeclaringClass() != Object.class) {
                    String name = m.getName();
                    if (name.startsWith("get") && !name.equals("getClass")) {
                        // Skip getters that return complex non-deterministic objects
                        Class<?> ret = m.getReturnType();
                        if (ret == String.class || ret.isPrimitive() || ret == Boolean.class
                                || ret == Integer.class || ret == Long.class
                                || ret.getName().equals("hudson.util.Secret")
                                || ret.isEnum()) {
                            getters.add(m);
                        }
                    }
                }
            }
            getters.sort(java.util.Comparator.comparing(Method::getName));
            for (Method m : getters) {
                try {
                    Object val = m.invoke(cred);
                    sb.append(m.getName()).append('=');
                    sb.append(stringifyCredentialValue(val));
                    sb.append(';');
                } catch (ReflectiveOperationException | RuntimeException e) {
                    LOGGER.log(Level.FINE, "Failed to read credential getter for hashing: {0}", m.getName());
                }
            }
            int hash = sb.toString().hashCode();
            LOGGER.log(Level.FINE, "Credential hash for {0}: {1}",
                    new Object[]{extractCredentialId(cred), hash});
            return hash;
        } catch (RuntimeException e) {
            return cred.hashCode();
        }
    }

    private static String stringifyCredentialValue(Object value) {
        if (value == null) {
            return "null";
        }
        if ("hudson.util.Secret".equals(value.getClass().getName())) {
            try {
                Method getEncryptedValue = value.getClass().getMethod("getEncryptedValue");
                Object encryptedValue = getEncryptedValue.invoke(value);
                return encryptedValue != null ? encryptedValue.toString() : "null";
            } catch (ReflectiveOperationException e) {
                LOGGER.log(Level.FINE, "Failed to read encrypted Secret value for credential hashing", e);
            }
        }
        return value.toString();
    }

    private static String currentUser() {
        // 1. Try pre-chain authenticated user (captured by PluginServletFilter BEFORE
        //    Jenkins impersonates SYSTEM for save operations) — most reliable source
        try {
            String preChain = RequestHolder.getAuthenticatedUser();
            if (isRealUser(preChain)) {
                LOGGER.log(Level.FINE, "currentUser from pre-chain ThreadLocal: {0}", preChain);
                return preChain;
            }
        } catch (Exception ignored) {}
        // 2. Try session-based Spring Security context — preserves original
        //    logged-in user even when Jenkins impersonates SYSTEM internally
        try {
            HttpServletRequest req = RequestHolder.get();
            if (req != null) {
                HttpSession session = req.getSession(false);
                if (session != null) {
                    Object ctx = session.getAttribute("SPRING_SECURITY_CONTEXT");
                    if (ctx != null) {
                        Method getAuth = ctx.getClass().getMethod("getAuthentication");
                        Object auth = getAuth.invoke(ctx);
                        if (auth != null) {
                            Method getName = auth.getClass().getMethod("getName");
                            String name = (String) getName.invoke(auth);
                            if (isRealUser(name)) {
                                LOGGER.log(Level.FINE, "currentUser from session SecurityContext: {0}", name);
                                return name;
                            }
                        }
                    }
                }
                // 3. Try getRemoteUser() — servlet container auth
                String remoteUser = req.getRemoteUser();
                if (isRealUser(remoteUser)) {
                    LOGGER.log(Level.FINE, "currentUser from remoteUser: {0}", remoteUser);
                    return remoteUser;
                }
                // 4. Try getUserPrincipal()
                java.security.Principal p = req.getUserPrincipal();
                if (p != null && isRealUser(p.getName())) {
                    LOGGER.log(Level.FINE, "currentUser from principal: {0}", p.getName());
                    return p.getName();
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "RequestHolder user lookup failed", e);
        }
        // 5. Try Stapler request
        try {
            org.kohsuke.stapler.StaplerRequest2 req = Stapler.getCurrentRequest2();
            if (req != null) {
                String remoteUser = req.getRemoteUser();
                if (isRealUser(remoteUser)) return remoteUser;
                java.security.Principal p = req.getUserPrincipal();
                if (p != null && isRealUser(p.getName())) return p.getName();
            }
        } catch (Exception ignored) {}
        // 6. Try Jenkins User.current() — may return SYSTEM if impersonated
        try {
            User u = User.current();
            if (u != null && isRealUser(u.getId())) return u.getId();
        } catch (Exception ignored) {}
        // 7. Try Spring SecurityContext (thread-local — may be impersonated)
        try {
            org.springframework.security.core.Authentication auth =
                    org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && isRealUser(auth.getName())) {
                return auth.getName();
            }
        } catch (Exception ignored) {}
        return "SYSTEM";
    }

    private static boolean isRealUser(String name) {
        return name != null && !name.isEmpty()
                && !"SYSTEM".equalsIgnoreCase(name)
                && !"anonymous".equalsIgnoreCase(name)
                && !"anonymousUser".equals(name);
    }

    static boolean shouldSuppressThemeUserPreferenceLog(String className,
                                                        boolean isUserSave,
                                                        String requestUri,
                                                        Set<String> parameterNames) {
        if (className == null || className.isEmpty()) {
            return false;
        }

        if (USER_THEME_SAVEABLE_CLASS_NAMES.contains(className)) {
            return true;
        }

        if (!isUserSave) {
            return false;
        }

        String normalizedUri = requestUri == null ? "" : requestUri.toLowerCase(java.util.Locale.ENGLISH);
        if (normalizedUri.startsWith("/theme/") || normalizedUri.contains("/theme/")) {
            return true;
        }

        for (String parameterName : parameterNames) {
            String normalizedName = parameterName.toLowerCase(java.util.Locale.ENGLISH);
            if (normalizedName.contains("theme") || normalizedName.contains("appearance")) {
                return true;
            }
        }

        return false;
    }

    static boolean shouldSuppressRequestScopedSystemConfigSave(boolean isSystemSave, String requestUri) {
        return isSystemSave && RouteAwareUrlMatcher.isConfigurationChange(requestUri);
    }

    private static String currentRequestUri() {
        try {
            HttpServletRequest request = RequestHolder.get();
            if (request != null && request.getRequestURI() != null) {
                return request.getRequestURI();
            }
        } catch (Exception ignored) {
        }

        try {
            var request = Stapler.getCurrentRequest2();
            if (request != null && request.getRequestURI() != null) {
                return request.getRequestURI();
            }
        } catch (Exception ignored) {
        }

        return "";
    }

    private static Set<String> currentRequestParameterNames() {
        try {
            HttpServletRequest request = RequestHolder.get();
            if (request != null) {
                return request.getParameterMap().keySet();
            }
        } catch (Exception ignored) {
        }

        try {
            var request = Stapler.getCurrentRequest2();
            if (request != null) {
                return request.getParameterMap().keySet();
            }
        } catch (Exception ignored) {
        }

        return Collections.emptySet();
    }
}
