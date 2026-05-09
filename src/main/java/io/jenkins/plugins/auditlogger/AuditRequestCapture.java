package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestEvent;
import jakarta.servlet.ServletRequestListener;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jenkins.model.Jenkins;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Registers a ServletRequestListener to capture HTTP requests in ThreadLocal.
 *
 * Priority: ServletRequestListener fires BEFORE any filter chain, guaranteeing
 * the request is available when SecurityListener.authenticated2() runs.
 * Falls back to PluginServletFilter if listener registration fails
 * (common when Jetty context is already fully initialized).
 */
@Extension
public class AuditRequestCapture {
    private static final Logger LOGGER = Logger.getLogger(AuditRequestCapture.class.getName());
    private static volatile boolean registered = false;

    @Initializer(after = InitMilestone.STARTED)
    public static void register() {
        if (registered) return;
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins == null) return;
            var ctx = jenkins.servletContext;
            ctx.addListener(new ServletRequestListener() {
                @Override
                public void requestInitialized(ServletRequestEvent sre) {
                    if (sre.getServletRequest() instanceof HttpServletRequest) {
                        RequestHolder.set((HttpServletRequest) sre.getServletRequest());
                    }
                }

                @Override
                public void requestDestroyed(ServletRequestEvent sre) {
                    if (sre.getServletRequest() instanceof HttpServletRequest) {
                        HttpServletRequest req = (HttpServletRequest) sre.getServletRequest();
                        enrichPendingAuthEntry(req);
                        detectAdminAction(req);
                    }
                    RequestHolder.clear();
                }
            });
            registered = true;
            LOGGER.info("AuditRequestCapture: ServletRequestListener registered");
        } catch (IllegalStateException | UnsupportedOperationException e) {
            LOGGER.log(Level.FINE, "ServletRequestListener registration is not supported, using PluginServletFilter fallback", e);
            registerFallbackFilter();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "ServletRequestListener registration failed, using fallback", e);
            registerFallbackFilter();
        }
    }

    private static void registerFallbackFilter() {
        try {
            hudson.util.PluginServletFilter.addFilter(new Filter() {
                @Override
                public void init(FilterConfig fc) {}

                @Override
                public void doFilter(ServletRequest req, ServletResponse res,
                                     FilterChain chain)
                        throws java.io.IOException, ServletException {
                    if (req instanceof HttpServletRequest) {
                        HttpServletRequest httpReq = (HttpServletRequest) req;
                        RequestHolder.set(httpReq);
                        // Capture the authenticated username BEFORE chain.doFilter() —
                        // Jenkins may impersonate SYSTEM during save operations,
                        // but at this point the real user is still in the SecurityContext.
                        String preChainUser = resolveUsername(httpReq);
                        if (preChainUser != null) {
                            RequestHolder.setAuthenticatedUser(preChainUser);
                        }
                    }
                    try {
                        chain.doFilter(req, res);
                    } finally {
                        // Enrich AFTER chain — security chain has already run by the
                        // time PluginServletFilter is invoked, so SecurityContext is
                        // populated and we can resolve the username for pending entries.
                        if (req instanceof HttpServletRequest) {
                            // Re-capture username in case it wasn't resolved before chain
                            if (RequestHolder.getAuthenticatedUser() == null) {
                                String postChainUser = resolveUsername((HttpServletRequest) req);
                                if (postChainUser != null) {
                                    RequestHolder.setAuthenticatedUser(postChainUser);
                                }
                            }
                            enrichPendingAuthEntry((HttpServletRequest) req);
                            detectAdminAction((HttpServletRequest) req);
                        }
                        RequestHolder.clear();
                    }
                }

                @Override
                public void destroy() {}
            });
            registered = true;
            LOGGER.info("AuditRequestCapture: PluginServletFilter fallback registered");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to register fallback filter — IP capture will rely on thread name parsing", e);
        }
    }

    /**
     * Detect critical admin operations using route-aware URL matching.
     * 
     * SECURITY IMPROVEMENTS:
     * - Uses RouteAwareUrlMatcher instead of naive string matching
     * - Prevents bypass via arbitrary prefixes/suffixes
     * - Detects script console access (critical security event)
     * - Validates URI structure before classification
     * 
     * Covers: Safe Restart, Plugin Operations, Security Config, Script Console.
     */
    private static void detectAdminAction(HttpServletRequest req) {
        try {
            String method = req.getMethod();
            // Also check GET for script console access (some endpoints are GET)
            if (!("POST".equalsIgnoreCase(method) || "GET".equalsIgnoreCase(method))) {
                return;
            }

            String uri = req.getRequestURI();
            if (uri == null) return;

            // Normalize: strip context path
            String ctx = req.getContextPath();
            if (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) {
                uri = uri.substring(ctx.length());
            }

            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            boolean pluginEventsEnabled = config == null || config.isEnablePluginEvents();
            boolean systemConfigEventsEnabled = config != null && config.isEnableSystemConfigEvents();

            String username = resolveUsername(req);
            if (username == null) username = "anonymous";

            String action = null;
            String target = null;
            String details = null;
            String severity = "HIGH";

            // ===== RESTART (route-aware matching) =====
            // Now prevents bypass via /static/lol/restart or /job/restart
            if ("POST".equalsIgnoreCase(method) && RouteAwareUrlMatcher.isRestartAction(uri)) {
                action = "SYSTEM_RESTART";
                target = "Jenkins";
                boolean isSafe = uri.contains("safe");
                details = (isSafe ? "Safe" : "Immediate") + " restart initiated by " + username;
                severity = "CRITICAL";
            }
            // ===== SCRIPT CONSOLE ACCESS (NEW - CRITICAL SECURITY) =====
            // Detects script console/scriptText access regardless of URL structure.
            // Record a single audit row here so one request does not fan out into duplicates.
            else if (systemConfigEventsEnabled && RouteAwareUrlMatcher.isScriptConsoleAccess(uri)) {
                action = "SCRIPT_CONSOLE_ACCESS";
                target = "ScriptConsole";
                String scriptContent = req.getParameter("script");
                if (scriptContent != null && !scriptContent.isEmpty()) {
                    String preview = scriptContent.substring(0, Math.min(50, scriptContent.length()));
                    details = "Script console access: " + preview + "... | Source: " + uri + " | User: " + username;
                } else {
                    details = "Script console access: N/A | Source: " + uri + " | User: " + username;
                }
                severity = "CRITICAL";
            }
            // ===== PLUGIN OPERATIONS (route-aware matching) =====
            else if (pluginEventsEnabled && "POST".equalsIgnoreCase(method) && RouteAwareUrlMatcher.isPluginManagerAction(uri)) {
                String pluginAction = classifyPluginAction(uri);
                if ("PLUGIN_INSTALLED".equals(pluginAction)) {
                    action = "PLUGIN_INSTALLED";
                    target = extractPluginTarget(req, uri);
                    details = "Plugin installed: " + target + " by " + username;
                } else if ("PLUGIN_REMOVED".equals(pluginAction)) {
                    action = "PLUGIN_REMOVED";
                    target = RouteAwareUrlMatcher.extractPluginName(uri);
                    if (target == null) target = "unknown-plugin";
                    details = "Plugin removed: " + target + " by " + username;
                    severity = "CRITICAL";
                } else if ("PLUGIN_UPDATED".equals(pluginAction)) {
                    action = "PLUGIN_UPDATED";
                    target = extractPluginTarget(req, uri);
                    details = "Plugin updated: " + target + " by " + username;
                } else if ("PLUGIN_ENABLED".equals(pluginAction) || "PLUGIN_DISABLED".equals(pluginAction)) {
                    action = pluginAction;
                    boolean enable = "PLUGIN_ENABLED".equals(pluginAction);
                    target = RouteAwareUrlMatcher.extractPluginName(uri);
                    if (target == null) target = "unknown-plugin";
                    details = "Plugin " + (enable ? "enabled" : "disabled") + ": " + target + " by " + username;
                }
            }
            // ===== CONFIGURATION CHANGES (route-aware matching) =====
            else if ("POST".equalsIgnoreCase(method) && systemConfigEventsEnabled && RouteAwareUrlMatcher.isConfigurationChange(uri)) {
                if (uri.contains("configureSecurity")) {
                    action = "SECURITY_CONFIG_UPDATED";
                    target = "SecurityRealm";
                    details = "Security configuration updated by " + username;
                    severity = "CRITICAL";
                } else {
                    action = "GLOBAL_CONFIG_UPDATED";
                    target = "GlobalConfig";
                    details = "Global configuration updated by " + username;
                    severity = "HIGH";
                }
            }

            if (action != null) {
                AuditLogEntry entry = new AuditLogEntry(username, action, target, details);
                entry.setSeverity(severity);
                AuditLogStorage.getInstance().addEntry(entry);
                LOGGER.log(Level.INFO, "{0}: target={1} by user={2}",
                        new Object[]{action, target, username});
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error detecting admin action", e);
        }
    }

    /** Extract plugin name(s) from install request parameters or URI. */
    private static String extractPluginTarget(HttpServletRequest req, String uri) {
        try {
            // For /pluginManager/installNecessaryPlugins, plugin names in body
            // For /pluginManager/install, check 'pluginName' or 'name' parameter
            String name = req.getParameter("pluginName");
            if (name == null) name = req.getParameter("name");
            if (name != null) return name;
            // Jenkins sends plugin selections as plugin.{name}.default=on
            java.util.Enumeration<String> paramNames = req.getParameterNames();
            if (paramNames != null) {
                StringBuilder plugins = new StringBuilder();
                while (paramNames.hasMoreElements()) {
                    String param = paramNames.nextElement();
                    if (param.startsWith("plugin.") && param.endsWith(".default")) {
                        String pluginName = param.substring("plugin.".length(),
                                param.length() - ".default".length());
                        if (plugins.length() > 0) plugins.append(", ");
                        plugins.append(pluginName);
                    }
                }
                if (plugins.length() > 0) return plugins.toString();
            }
            // For upload: filename from multipart
            if (uri.contains("upload")) return "uploaded-plugin";
        } catch (Exception ignored) {}
        return "plugin(s)";
    }

    static boolean isPluginInstallUri(String uri) {
        // Use route-aware matching instead of naive contains()
        // Prevents false positives like /job/myplugins/...
        return RouteAwareUrlMatcher.isPluginManagerAction(uri) &&
               (uri.contains("/install") || uri.contains("/uploadPlugin"));
    }

    static boolean isPluginUpdateUri(String uri) {
        // Route-aware matching for plugin update endpoints
        return RouteAwareUrlMatcher.isPluginManagerAction(uri) &&
               uri.matches(".*/pluginManager/(deploy|update)$");
    }

    static String classifyPluginAction(String uri) {
        if (uri == null || !RouteAwareUrlMatcher.isPluginManagerAction(uri)) {
            return null;
        }
        
        // Route-aware classification of plugin actions
        if ((uri.contains("/pluginManager/plugin/") || uri.contains("/plugin/")) && 
            (uri.contains("/uninstall") || uri.endsWith("/doUninstall"))) {
            return "PLUGIN_REMOVED";
        }
        if ((uri.contains("/pluginManager/plugin/") || uri.contains("/plugin/")) && 
            (uri.contains("/makeEnabled") || uri.contains("/enable"))) {
            return "PLUGIN_ENABLED";
        }
        if ((uri.contains("/pluginManager/plugin/") || uri.contains("/plugin/")) && 
            (uri.contains("/makeDisabled") || uri.contains("/disable"))) {
            return "PLUGIN_DISABLED";
        }
        if (uri.contains("/pluginManager/") && 
            (uri.contains("/install") || uri.contains("/deploy") || uri.contains("/update"))) {
            return "PLUGIN_INSTALLED";
        }
        return null;
    }

    /** 
     * Extract plugin name from URI using route-aware matching.
     * More reliable than splitting by "/" which fails with complex paths.
     */
    static String extractPluginNameFromUri(String uri) {
        String name = RouteAwareUrlMatcher.extractPluginName(uri);
        return name != null ? name : "unknown-plugin";
    }

    /**
     * Enrich a pending auth entry (created by SecurityListener before PluginServletFilter ran)
     * with User-Agent from the now-available HTTP request, then write it to the audit log.
     * For form logins, this runs on the REDIRECT request (the browser follows the 302).
     * For API calls, this runs on the SAME request (filter chain continues after security).
     */
    private static void enrichPendingAuthEntry(HttpServletRequest req) {
        String username = resolveUsername(req);
        if (username == null) return;

        AuditLogEntry entry = RequestHolder.consumePendingAuthEntry(username);
        if (entry == null) return;
        try {
            String ua = req.getHeader("User-Agent");
            if (ua != null) {
                entry.setUserAgent(ua);
                // Update the details string to include the actual UA
                String details = entry.getDetails();
                if (details != null && details.contains("UA: N/A")) {
                    entry.setDetails(details.replace("UA: N/A", "UA: " + shorten(ua)));
                }
            }

            // Re-detect auth method from actual request headers (more accurate than thread name)
            String authHeader = req.getHeader("Authorization");
            if (authHeader != null) {
                String method = null;
                if (authHeader.regionMatches(true, 0, "Basic ", 0, 6)) method = "basic-auth";
                else if (authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) method = "bearer-token";
                else if (authHeader.regionMatches(true, 0, "Negotiate ", 0, 10)) method = "kerberos-spnego";
                if (method != null && entry.getAuthMethod() != null) {
                    entry.setAuthMethod(method);
                }
            }

            AuditLogStorage.getInstance().addEntry(entry);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to enrich pending auth entry", e);
        }
    }

    /** Resolve the authenticated username from the request. */
    private static String resolveUsername(HttpServletRequest req) {
        // 1. Try session-based Spring Security context (preserves real user even in impersonated context)
        try {
            HttpSession session = req.getSession(false);
            if (session != null) {
                Object ctx = session.getAttribute("SPRING_SECURITY_CONTEXT");
                if (ctx != null) {
                    java.lang.reflect.Method getAuth = ctx.getClass().getMethod("getAuthentication");
                    Object auth = getAuth.invoke(ctx);
                    if (auth != null) {
                        java.lang.reflect.Method getName = auth.getClass().getMethod("getName");
                        String name = (String) getName.invoke(auth);
                        if (name != null && !name.isEmpty()
                                && !"anonymous".equalsIgnoreCase(name)
                                && !"SYSTEM".equalsIgnoreCase(name)) {
                            return name;
                        }
                    }
                }
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
        // 2. Try getRemoteUser()
        String remoteUser = req.getRemoteUser();
        if (remoteUser != null && !remoteUser.isEmpty()
                && !"anonymous".equalsIgnoreCase(remoteUser)) {
            return remoteUser;
        }
        // 3. Try getUserPrincipal()
        Principal p = req.getUserPrincipal();
        if (p != null && p.getName() != null && !p.getName().isEmpty()
                && !"anonymous".equalsIgnoreCase(p.getName())) {
            return p.getName();
        }
        // 4. Try thread-local Spring SecurityContext
        org.springframework.security.core.Authentication auth =
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null && !auth.getName().isEmpty()
                && !"anonymous".equalsIgnoreCase(auth.getName())
                && !"anonymousUser".equals(auth.getName())
                && !"SYSTEM".equalsIgnoreCase(auth.getName())) {
            return auth.getName();
        }
        return null;
    }

    private static String shorten(String s) {
        if (s == null) return "N/A";
        String clean = s.replaceAll("[\\r\\n\\t]", " ");
        return clean.length() > 80 ? clean.substring(0, 80) + "..." : clean;
    }

    /**
     * Safety net: no longer needed since pending entries are in a static map
     * with TTL-based expiry, not a ThreadLocal. Kept as no-op for call sites.
     */
    private static void flushPendingAuthEntry() {
        // No-op — cross-request pending map handles its own expiry
    }
}
