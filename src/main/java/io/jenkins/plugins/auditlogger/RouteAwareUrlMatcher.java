package io.jenkins.plugins.auditlogger;

import java.util.logging.Logger;

/**
 * Route-aware URL matching for security-critical Jenkins operations.
 * 
 * SECURITY: Replaces naive string matching (contains/endsWith) with proper
 * route analysis. Prevents bypass via:
 * - Arbitrary prefixes (/static/lol/restart)
 * - Arbitrary suffixes (query params, fragments)
 * - Job/view names that happen to match keywords
 * - Jenkins' flexible path routing
 * 
 * Methodology:
 * 1. Normalize the URI (strip context, fragments, query params)
 * 2. Parse the path into segments
 * 3. Match against known action patterns
 * 4. Validate segment count and structure
 * 5. Extract relevant identifiers
 */
public class RouteAwareUrlMatcher {
    private static final Logger LOGGER = Logger.getLogger(RouteAwareUrlMatcher.class.getName());

    /**
     * Checks if URI is a restart action endpoint.
     * Valid patterns:
     * - /restart, /safeRestart (global)
     * - /manage/restart, /manage/safeRestart (manage page)
    * - /updateCenter/restart, /updateCenter/safeRestart (post-plugin-install flow)
     * 
     * Invalid patterns that would bypass string matching:
     * - /static/restart (prefix noise)
     * - /job/restart (job name collision)
     * - /view/script (view name "script")
     */
    public static boolean isRestartAction(String uri) {
        if (uri == null || uri.isEmpty()) return false;
        
        String normalized = normalizeUri(uri);
        String[] segments = normalized.split("/");
        
        // Must have exact form: "" / "restart" or "" / "safeRestart"
        if (segments.length == 2 && segments[0].isEmpty()) {
            String action = segments[1];
            return "restart".equals(action) || "safeRestart".equals(action);
        }
        
        // Or: "" / "manage" / "restart" or "" / "manage" / "safeRestart"
        if (segments.length == 3 && segments[0].isEmpty() && "manage".equals(segments[1])) {
            String action = segments[2];
            return "restart".equals(action) || "safeRestart".equals(action);
        }

        // Or: "" / "updateCenter" / "restart" or "" / "updateCenter" / "safeRestart"
        if (segments.length == 3 && segments[0].isEmpty() && "updateCenter".equals(segments[1])) {
            String action = segments[2];
            return "restart".equals(action) || "safeRestart".equals(action);
        }
        
        return false;
    }

    /**
     * Checks if URI accesses plugin manager endpoints.
     * Valid patterns must start with /pluginManager or /plugin and NOT be
     * something like /job/plugins/...
     */
    public static boolean isPluginManagerAction(String uri) {
        if (uri == null || uri.isEmpty()) return false;
        
        String normalized = normalizeUri(uri);
        String[] segments = normalized.split("/");
        
        if (segments.length < 2 || !segments[0].isEmpty()) {
            return false; // Must start with /
        }
        
        // Root-level plugin routes: /pluginManager/... or /plugin/...
        String firstAction = segments[1];
        if ("pluginManager".equals(firstAction) || "plugin".equals(firstAction)) {
            return true;
        }

        // Managed plugin routes: /manage/pluginManager/...
        if (segments.length >= 3 && "manage".equals(firstAction) && "pluginManager".equals(segments[2])) {
            return true;
        }
        
        return false;
    }

    /**
     * Checks if URI is an exact plugin installation endpoint.
     */
    public static boolean isPluginInstallAction(String uri) {
        if (uri == null || uri.isEmpty()) return false;

        String normalized = normalizeUri(uri);
        String[] segments = normalized.split("/");

        if (segments.length == 3 && segments[0].isEmpty() && "pluginManager".equals(segments[1])) {
            return isTerminalAction(segments[2], "install", "installNecessaryPlugins", "installPlugins", "uploadPlugin");
        }

        if (segments.length == 4 && segments[0].isEmpty() && "manage".equals(segments[1])
                && "pluginManager".equals(segments[2])) {
            return isTerminalAction(segments[3], "install", "installNecessaryPlugins", "installPlugins", "uploadPlugin");
        }

        return false;
    }

    /**
     * Checks if URI is an exact plugin update endpoint.
     */
    public static boolean isPluginUpdateAction(String uri) {
        if (uri == null || uri.isEmpty()) return false;

        String normalized = normalizeUri(uri);
        String[] segments = normalized.split("/");

        if (segments.length == 3 && segments[0].isEmpty() && "pluginManager".equals(segments[1])) {
            return isTerminalAction(segments[2], "update", "deploy");
        }

        if (segments.length == 4 && segments[0].isEmpty() && "manage".equals(segments[1])
                && "pluginManager".equals(segments[2])) {
            return isTerminalAction(segments[3], "update", "deploy");
        }

        return false;
    }

    /**
     * Classifies exact plugin lifecycle endpoints for enable, disable, and uninstall actions.
     */
    public static String classifyPluginLifecycleAction(String uri) {
        if (uri == null || uri.isEmpty()) return null;

        String normalized = normalizeUri(uri);
        String[] segments = normalized.split("/");

        if (segments.length == 4 && segments[0].isEmpty() && "plugin".equals(segments[1])) {
            return resolvePluginLifecycleAction(segments[3]);
        }

        if (segments.length == 5 && segments[0].isEmpty() && "pluginManager".equals(segments[1])
                && "plugin".equals(segments[2])) {
            return resolvePluginLifecycleAction(segments[4]);
        }

        if (segments.length == 6 && segments[0].isEmpty() && "manage".equals(segments[1])
                && "pluginManager".equals(segments[2]) && "plugin".equals(segments[3])) {
            return resolvePluginLifecycleAction(segments[5]);
        }

        return null;
    }

    /**
     * Checks if URI is a configuration/security change endpoint.
     * Valid patterns:
     * - /configureSecurity, /manage/configureSecurity, /manage/configureSecurity/configure
     * - /manage/configure, /configSubmit, /manage/configSubmit
     */
    public static boolean isConfigurationChange(String uri) {
        if (uri == null || uri.isEmpty()) return false;
        
        String normalized = normalizeUri(uri);
        String[] segments = normalized.split("/");
        
        if (segments.length < 2 || !segments[0].isEmpty()) {
            return false;
        }
        
        // Check for /configureSecurity and its form submit route
        if ((segments.length == 2 && "configureSecurity".equals(segments[1])) ||
            (segments.length == 3 && "manage".equals(segments[1]) && "configureSecurity".equals(segments[2])) ||
            (segments.length == 4 && "manage".equals(segments[1])
                    && "configureSecurity".equals(segments[2])
                    && "configure".equals(segments[3]))) {
            return true;
        }
        
        // Check for /manage/configure, /configSubmit, /manage/configSubmit
        if ((segments.length == 3 && "manage".equals(segments[1]) && "configure".equals(segments[2])) ||
            (segments.length == 2 && "configSubmit".equals(segments[1])) ||
            (segments.length == 3 && "manage".equals(segments[1]) && "configSubmit".equals(segments[2]))) {
            return true;
        }
        
        return false;
    }

    private static boolean isTerminalAction(String candidate, String... allowedActions) {
        for (String allowedAction : allowedActions) {
            if (allowedAction.equals(candidate)) {
                return true;
            }
        }
        return false;
    }

    private static String resolvePluginLifecycleAction(String actionSegment) {
        if (actionSegment == null || actionSegment.isEmpty()) {
            return null;
        }

        switch (actionSegment) {
            case "uninstall":
            case "doUninstall":
                return "PLUGIN_REMOVED";
            case "makeEnabled":
            case "enable":
                return "PLUGIN_ENABLED";
            case "makeDisabled":
            case "disable":
                return "PLUGIN_DISABLED";
            default:
                return null;
        }
    }

    /**
     * Extracts the parameter value safely from URI.
     * Handles URL encoding and prevents injection via getQueryParams.
     */
    public static String extractUriParameter(String uri, String paramName) {
        if (uri == null || paramName == null) return null;
        
        try {
            // Get query string if present
            int qIndex = uri.indexOf('?');
            if (qIndex == -1) return null;
            
            String queryString = uri.substring(qIndex + 1);
            String[] pairs = queryString.split("&");
            
            for (String pair : pairs) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2 && paramName.equals(java.net.URLDecoder.decode(kv[0], "UTF-8"))) {
                    return java.net.URLDecoder.decode(kv[1], "UTF-8");
                }
            }
        } catch (Exception e) {
            // Return null on any parsing error
        }
        
        return null;
    }

    /**
     * Normalizes URI by removing context path, query params, fragments.
     * /app/job/test/script?foo=bar#section → /job/test/script
     */
    private static String normalizeUri(String uri) {
        if (uri == null) return "";
        
        // Remove query string and fragment
        int qIndex = uri.indexOf('?');
        int hIndex = uri.indexOf('#');
        int endIndex = uri.length();
        
        if (qIndex != -1) endIndex = Math.min(endIndex, qIndex);
        if (hIndex != -1) endIndex = Math.min(endIndex, hIndex);
        
        String normalized = uri.substring(0, endIndex);
        
        // Remove trailing slash
        if (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        
        return normalized;
    }

    /**
     * Extracts plugin name from plugin manager URIs.
     * /pluginManager/plugin/git/uninstall → git
     * /plugin/git/doUninstall → git
     */
    public static String extractPluginName(String uri) {
        if (uri == null) return null;
        
        String normalized = normalizeUri(uri);
        String[] segments = normalized.split("/");
        
        // Pattern: /pluginManager/plugin/{name}/{action}
        for (int i = 0; i < segments.length - 1; i++) {
            if ("plugin".equals(segments[i]) && i + 1 < segments.length) {
                String name = segments[i + 1];
                // Validate it's not empty or a known action keyword
                if (!name.isEmpty() && !name.matches("(do|make)(Enabled|Disabled|Uninstall|Install)")) {
                    return name;
                }
            }
        }
        
        return null;
    }

    /**
     * Checks if a URI path segment is a known Jenkins job/item name vs. a route keyword.
     * This helps prevent false positives where a job happens to be named "script" or "restart".
     */
    public static boolean isLikelyJobName(String segment) {
        if (segment == null || segment.isEmpty()) return false;
        
        // Known Jenkins route keywords that should NOT be treated as job names
        String[] keywords = {
            "job", "view", "user", "plugin", "pluginManager", "manage", "configure",
            "configureSecurity", "script", "restart", "safeRestart", "api", "queue",
            "cli", "login", "logout", "about", "help", "audit", "metrics"
        };
        
        for (String keyword : keywords) {
            if (keyword.equals(segment.toLowerCase())) {
                return false;
            }
        }
        
        return true;
    }
}
