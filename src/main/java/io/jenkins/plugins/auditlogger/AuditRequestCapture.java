package io.jenkins.plugins.auditlogger;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import hudson.init.InitMilestone;
import hudson.init.Initializer;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestEvent;
import jakarta.servlet.ServletRequestListener;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpSession;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * Registers a ServletRequestListener to capture HTTP requests in ThreadLocal.
 *
 * Priority: ServletRequestListener fires BEFORE any filter chain, guaranteeing
 * the request is available when SecurityListener.authenticated2() runs.
 * Falls back to PluginServletFilter if listener registration fails
 * (common when Jetty context is already fully initialized).
 */
public class AuditRequestCapture {
    private static final Logger LOGGER = Logger.getLogger(AuditRequestCapture.class.getName());
    private static final String CACHED_REQUEST_BODY_ATTR = AuditRequestCapture.class.getName() + ".cachedRequestBody";
    private static final Pattern MULTIPART_FILE_NAME_PATTERN =
            Pattern.compile("filename=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern MULTIPART_FIELD_PATTERN =
            Pattern.compile("name=\"(?:pluginName|pluginUrl|url|name)\"\\s*\\r?\\n\\r?\\n([^\\r\\n]+)",
                    Pattern.CASE_INSENSITIVE);
    private static volatile boolean registered = false;

    @Initializer(after = InitMilestone.STARTED)
    public static void register() {
        if (registered) return;
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins == null) return;
            var ctx = jenkins.getServletContext();
            if (ctx == null) {
                registerFallbackFilter();
                return;
            }
            ctx.addListener(new ServletRequestListener() {
                @Override
                public void requestInitialized(ServletRequestEvent sre) {
                    if (sre.getServletRequest() instanceof HttpServletRequest) {
                        HttpServletRequest req = (HttpServletRequest) sre.getServletRequest();
                        RequestHolder.set(req);
                        String preChainUser = resolveUsername(req);
                        if (preChainUser != null) {
                            RequestHolder.setAuthenticatedUser(preChainUser);
                        }
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
                    HttpServletRequest effectiveReq = null;
                    if (req instanceof HttpServletRequest) {
                        HttpServletRequest httpReq = (HttpServletRequest) req;
                        effectiveReq = cacheRequestBody(httpReq);
                        RequestHolder.set(effectiveReq);
                        // Capture the authenticated username BEFORE chain.doFilter() —
                        // Jenkins may impersonate SYSTEM during save operations,
                        // but at this point the real user is still in the SecurityContext.
                        String preChainUser = resolveUsername(effectiveReq);
                        if (preChainUser != null) {
                            RequestHolder.setAuthenticatedUser(preChainUser);
                        }
                    }
                    try {
                        chain.doFilter(effectiveReq != null ? effectiveReq : req, res);
                    } finally {
                        // Enrich AFTER chain — security chain has already run by the
                        // time PluginServletFilter is invoked, so SecurityContext is
                        // populated and we can resolve the username for pending entries.
                        if (effectiveReq != null) {
                            // Re-capture username in case it wasn't resolved before chain
                            if (RequestHolder.getAuthenticatedUser() == null) {
                                String postChainUser = resolveUsername(effectiveReq);
                                if (postChainUser != null) {
                                    RequestHolder.setAuthenticatedUser(postChainUser);
                                }
                            }
                            enrichPendingAuthEntry(effectiveReq);
                            detectAdminAction(effectiveReq);
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
    * Covers: Safe Restart, Plugin Operations, Security Config.
     */
    private static void detectAdminAction(HttpServletRequest req) {
        try {
            String method = req.getMethod();
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

            // ===== PLUGIN OPERATIONS (route-aware matching) =====
            if (pluginEventsEnabled && "POST".equalsIgnoreCase(method) && RouteAwareUrlMatcher.isPluginManagerAction(uri)) {
                String pluginAction = classifyPluginAction(uri);
                if ("PLUGIN_INSTALLED".equals(pluginAction) || "PLUGIN_UPDATED".equals(pluginAction)) {
                    String pluginTarget = extractPluginTarget(req, uri);
                    String resolvedPluginAction = resolvePluginAction(pluginAction, pluginTarget, AuditRequestCapture::isInstalledPlugin);
                    if (pluginTarget != null) {
                        action = resolvedPluginAction;
                        target = pluginTarget;
                        details = formatPluginActionDetails(resolvedPluginAction, target, username);
                    }
                } else if ("PLUGIN_REMOVED".equals(pluginAction)) {
                    action = "PLUGIN_REMOVED";
                    target = RouteAwareUrlMatcher.extractPluginName(uri);
                    if (target == null) target = "unknown-plugin";
                    details = "Plugin removed: " + target + " by " + username;
                    severity = "CRITICAL";
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
            else if (systemConfigEventsEnabled && RouteAwareUrlMatcher.isRestartAction(uri)) {
                action = "SYSTEM_RESTART";
                target = "Jenkins";
                details = formatRestartActionDetails(uri, username);
                severity = "CRITICAL";
                RequestHolder.setLastRestartInitiator(username);

                long now = System.currentTimeMillis();
                if (AuditRestartListener.shouldSuppressDuplicateRestartLog(now)) {
                    return;
                }
                AuditLogEntry entry = new AuditLogEntry(username, action, target, details, now);
                entry.setSeverity(severity);
                AuditLogStorage storage = AuditLogStorage.getInstance();
                storage.addEntry(entry);
                storage.flushNow();
                LOGGER.log(Level.INFO, "{0}: target={1} by user={2}",
                        new Object[]{action, target, username});
                return;
            }

            if (action != null) {
                AuditLogEntry entry = new AuditLogEntry(username, action, target, details);
                entry.setSeverity(severity);
                AuditLogStorage storage = AuditLogStorage.getInstance();
                storage.addEntry(entry);
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
            // For /pluginManager/installPlugins, plugins are sent as a JSON array body
            String name = req.getParameter("pluginName");
            if (name == null) name = req.getParameter("name");
            if (name == null) name = req.getParameter("pluginUrl");
            if (name == null) name = req.getParameter("url");
            String normalizedName = normalizePluginTarget(name);
            if (normalizedName != null) return normalizedName;

            String pluginsFromBody = extractPluginTargetFromRequestBody((String) req.getAttribute(CACHED_REQUEST_BODY_ATTR));
            if (pluginsFromBody != null) return pluginsFromBody;

            // Jenkins sends plugin selections as plugin.{name}.default=on
            Enumeration<String> paramNames = req.getParameterNames();
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
        } catch (Exception ignored) {}
        return null;
    }

    static String extractPluginTargetFromRequestBody(String requestBody) {
        String pluginsFromJson = extractPluginTargetFromJsonBody(requestBody);
        if (pluginsFromJson != null) {
            return pluginsFromJson;
        }

        String multipartTarget = extractPluginTargetFromMultipartBody(requestBody);
        if (multipartTarget != null) {
            return multipartTarget;
        }

        return extractPluginTargetFromFormBody(requestBody);
    }

    static String extractPluginTargetFromJsonBody(String requestBody) {
        if (requestBody == null || requestBody.isBlank()) {
            return null;
        }

        try {
            JSONObject json = JSONObject.fromObject(requestBody);
            Object pluginsValue = json.get("plugins");
            if (!(pluginsValue instanceof JSONArray plugins) || plugins.isEmpty()) {
                return null;
            }

            StringBuilder names = new StringBuilder();
            for (Object plugin : plugins) {
                if (plugin == null) {
                    continue;
                }
                String name = plugin instanceof JSONObject pluginObject
                        ? pluginObject.optString("name", pluginObject.optString("shortName", plugin.toString()))
                        : plugin.toString();
                name = normalizeSinglePluginToken(name);
                if (name.isBlank()) {
                    continue;
                }
                if (names.length() > 0) {
                    names.append(", ");
                }
                names.append(name);
            }

            return names.length() > 0 ? names.toString() : null;
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Failed to parse plugin install request body", e);
            return null;
        }
    }

    private static String extractPluginTargetFromMultipartBody(String requestBody) {
        if (requestBody == null || requestBody.isBlank()) {
            return null;
        }

        Matcher fileMatcher = MULTIPART_FILE_NAME_PATTERN.matcher(requestBody);
        if (fileMatcher.find()) {
            String normalized = normalizePluginTarget(fileMatcher.group(1));
            if (normalized != null) {
                return normalized;
            }
        }

        Matcher fieldMatcher = MULTIPART_FIELD_PATTERN.matcher(requestBody);
        while (fieldMatcher.find()) {
            String normalized = normalizePluginTarget(fieldMatcher.group(1));
            if (normalized != null) {
                return normalized;
            }
        }
        return null;
    }

    private static String extractPluginTargetFromFormBody(String requestBody) {
        if (requestBody == null || requestBody.isBlank()) {
            return null;
        }

        try {
            String decodedBody = URLDecoder.decode(requestBody, StandardCharsets.UTF_8);
            for (String pair : decodedBody.split("&")) {
                if (pair.isBlank()) {
                    continue;
                }
                int separatorIndex = pair.indexOf('=');
                String key = separatorIndex >= 0 ? pair.substring(0, separatorIndex) : pair;
                String value = separatorIndex >= 0 ? pair.substring(separatorIndex + 1) : "";
                if ("pluginName".equals(key) || "name".equals(key) || "pluginUrl".equals(key) || "url".equals(key)) {
                    String normalized = normalizePluginTarget(value);
                    if (normalized != null) {
                        return normalized;
                    }
                }
            }
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.FINE, "Failed to decode plugin install form body", e);
        }
        return null;
    }

    static boolean isPluginInstallUri(String uri) {
        return RouteAwareUrlMatcher.isPluginInstallAction(uri);
    }

    static boolean isPluginUpdateUri(String uri) {
        return RouteAwareUrlMatcher.isPluginUpdateAction(uri);
    }

    static String classifyPluginAction(String uri) {
        if (uri == null || !RouteAwareUrlMatcher.isPluginManagerAction(uri)) {
            return null;
        }

        String lifecycleAction = RouteAwareUrlMatcher.classifyPluginLifecycleAction(uri);
        if (lifecycleAction != null) {
            return lifecycleAction;
        }
        if (isPluginUpdateUri(uri)) {
            return "PLUGIN_UPDATED";
        }
        if (isPluginInstallUri(uri)) {
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

    static String resolvePluginAction(String pluginAction, String pluginTarget, Predicate<String> installedPluginLookup) {
        if (!"PLUGIN_INSTALLED".equals(pluginAction) || pluginTarget == null || installedPluginLookup == null) {
            return pluginAction;
        }

        boolean sawTarget = false;
        for (String token : pluginTarget.split("\\s*,\\s*")) {
            String normalized = normalizeSinglePluginToken(token);
            if (normalized.isBlank()) {
                continue;
            }
            sawTarget = true;
            if (!installedPluginLookup.test(normalized)) {
                return "PLUGIN_INSTALLED";
            }
        }
        return sawTarget ? "PLUGIN_UPDATED" : pluginAction;
    }

    static String normalizePluginTarget(String rawTarget) {
        if (rawTarget == null || rawTarget.isBlank()) {
            return null;
        }

        Set<String> normalizedTargets = new LinkedHashSet<>();
        for (String token : rawTarget.split("\\s*,\\s*")) {
            String normalized = normalizeSinglePluginToken(token);
            if (!normalized.isBlank()) {
                normalizedTargets.add(normalized);
            }
        }
        if (normalizedTargets.isEmpty()) {
            return null;
        }
        return String.join(", ", normalizedTargets);
    }

    static String formatPluginActionDetails(String pluginAction, String pluginTarget, String username) {
        boolean multiplePlugins = pluginTarget != null && pluginTarget.contains(",");
        String noun = multiplePlugins ? "Plugins" : "Plugin";
        String verb = "PLUGIN_UPDATED".equals(pluginAction) ? "updated" : "installed";
        return noun + " " + verb + ": " + pluginTarget + " by " + username;
    }

    static String formatRestartActionDetails(String uri, String username) {
        boolean safeRestart = RouteAwareUrlMatcher.isSafeRestartAction(uri);
        return (safeRestart ? "Safe" : "Immediate") + " restart initiated by " + username;
    }

    private static String normalizeSinglePluginToken(String rawToken) {
        if (rawToken == null) {
            return "";
        }

        String token = rawToken.trim();
        if (token.isEmpty()) {
            return "";
        }

        if (token.contains("://")) {
            int queryIndex = token.indexOf('?');
            if (queryIndex >= 0) {
                token = token.substring(0, queryIndex);
            }
            int hashIndex = token.indexOf('#');
            if (hashIndex >= 0) {
                token = token.substring(0, hashIndex);
            }
            int slashIndex = token.lastIndexOf('/');
            if (slashIndex >= 0 && slashIndex + 1 < token.length()) {
                token = token.substring(slashIndex + 1);
            }
        } else {
            token = token.replace('\\', '/');
            int slashIndex = token.lastIndexOf('/');
            if (slashIndex >= 0 && slashIndex + 1 < token.length()) {
                token = token.substring(slashIndex + 1);
            }
        }

        int atIndex = token.indexOf('@');
        if (atIndex > 0) {
            token = token.substring(0, atIndex);
        }
        int colonIndex = token.indexOf(':');
        if (colonIndex > 0 && token.indexOf("://") < 0) {
            token = token.substring(0, colonIndex);
        }
        if (token.endsWith(".jpi") || token.endsWith(".hpi")) {
            token = token.substring(0, token.length() - 4);
        }
        return token.trim();
    }

    private static boolean isInstalledPlugin(String shortName) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        return jenkins != null
                && jenkins.getPluginManager() != null
                && jenkins.getPluginManager().getPlugin(shortName) != null;
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
                String details = entry.getDetails();
                entry.setDetails(AuditUserAgentFormatter.replaceMissingInDetails(details, ua));
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
        String preChainUser = RequestHolder.getAuthenticatedUser();
        if (preChainUser != null && !preChainUser.isEmpty()
                && !"anonymous".equalsIgnoreCase(preChainUser)
                && !"anonymousUser".equalsIgnoreCase(preChainUser)
                && !"SYSTEM".equalsIgnoreCase(preChainUser)) {
            return preChainUser;
        }
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

    private static HttpServletRequest cacheRequestBody(HttpServletRequest request) throws IOException {
        String method = request.getMethod();
        String contentType = request.getContentType();
        if (!"POST".equalsIgnoreCase(method) || contentType == null
                || !contentType.toLowerCase(Locale.ROOT).contains("application/json")) {
            return request;
        }

        BufferedRequestWrapper wrapped = new BufferedRequestWrapper(request);
        wrapped.setAttribute(CACHED_REQUEST_BODY_ATTR, wrapped.getCachedBody());
        return wrapped;
    }

    private static final class BufferedRequestWrapper extends HttpServletRequestWrapper {
        private final byte[] body;
        private final Charset charset;

        BufferedRequestWrapper(HttpServletRequest request) throws IOException {
            super(request);
            this.body = request.getInputStream().readAllBytes();
            String encoding = request.getCharacterEncoding();
            this.charset = encoding != null ? Charset.forName(encoding) : StandardCharsets.UTF_8;
        }

        String getCachedBody() {
            return new String(body, charset);
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream input = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public int read() {
                    return input.read();
                }

                @Override
                public boolean isFinished() {
                    return input.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener readListener) {
                    // Synchronous wrapper; async callbacks are not needed here.
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }

    /**
     * Safety net: no longer needed since pending entries are in a static map
     * with TTL-based expiry, not a ThreadLocal. Kept as no-op for call sites.
     */
    private static void flushPendingAuthEntry() {
        // No-op — cross-request pending map handles its own expiry
    }
}
