package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import jakarta.servlet.http.HttpServletRequest;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Authentication event listener (login, logout, failed login).
 *
 * Key production fixes:
 * - Dedup applies ONLY to API/token auth, not interactive logins
 * - Dedup map bounded to 10,000 entries with periodic eviction
 * - IP extraction: WebAuthenticationDetails -> HttpServletRequest -> thread name
 */
@Extension
public class AuditSecurityListener extends jenkins.security.SecurityListener {
    private static final Logger LOGGER = Logger.getLogger(AuditSecurityListener.class.getName());

    private static final long API_AUTH_DEDUP_MS = 5 * 60 * 1000; // 5 min
    private static final int MAX_DEDUP_ENTRIES = 10_000;
    private final ConcurrentHashMap<String, Long> lastApiAuthTime = new ConcurrentHashMap<>();

    /** Dedup for failed logins — prevents double-logging when both failedToAuthenticate and failedToLogIn fire. */
    private static final long FAILED_LOGIN_DEDUP_MS = 2_000; // 2 second window
    private final ConcurrentHashMap<String, Long> lastFailedLoginTime = new ConcurrentHashMap<>();

    @Override
    protected void authenticated2(UserDetails details) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableAuthenticationEvents()) return;

            String username = details.getUsername();
            if (!isRealUser(username)) return;

            String ip = extractIp();
            String authMethod = detectAuthMethod();
            String userAgent = extractUserAgent();
            boolean isApiAuth = isApiAuthentication(authMethod);
            boolean isSsoAuth = isSsoAuthentication(authMethod);
            boolean hasRequest = !"N/A".equals(userAgent);

            // Only dedup API/token auth to prevent log flooding from CI tools.
            // Interactive (form) logins always get logged.
            if (isApiAuth) {
                long now = System.currentTimeMillis();
                Long last = lastApiAuthTime.get(username);
                if (last != null && (now - last) < API_AUTH_DEDUP_MS) return;
                lastApiAuthTime.put(username, now);
                evictStaleDedup(now);
            }

            String action;
            if (isApiAuth) {
                action = "API_AUTH";
            } else if (isSsoAuth) {
                action = "SSO_LOGIN";
            } else {
                action = "LOGIN";
            }

            String detail = buildAuthenticationDetail(authMethod, userAgent, isApiAuth, isSsoAuth);

            AuditLogEntry entry = AuditLogEntry.withAuth(username, action, "Jenkins", detail, ip, authMethod);
            RequestHolder.cacheUserIp(username, ip);
            String sessionId = extractSessionId();
            entry.setSessionId(sessionId);

            if (sessionId != null && !"N/A".equals(sessionId)) {
                AuditSessionListener.associateUsernameWithSession(sessionId, username);
            }

            if (hasRequest) {
                // Request is available — write immediately with full data
                entry.setUserAgent(userAgent);
                AuditLogStorage.getInstance().addEntry(entry);
            } else {
                // Request not available (authenticated2 fires inside Spring Security chain,
                // before PluginServletFilter). Store in cross-request map so AuditRequestCapture
                // can enrich with User-Agent on the next request from this user
                // (the redirect after form login, or the same request for API calls).
                RequestHolder.setPendingAuthEntry(username, entry);
            }

            LOGGER.log(Level.INFO, "{0}: user={1} ip={2} method={3} deferred={4}",
                    new Object[]{action, username, ip, authMethod, !hasRequest});
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error recording authentication event", e);
        }
    }

    @Override
    protected void loggedIn(String username) {
        // Intentionally empty — authenticated2 already records the event
    }

    @Override
    protected void failedToAuthenticate(String username) {
        recordFailedLogin(username);
    }

    @Override
    protected void failedToLogIn(String username) {
        // Jenkins 2.x+ calls failedToLogIn for form login failures
        // instead of failedToAuthenticate. Handle both.
        recordFailedLogin(username);
    }

    private void recordFailedLogin(String username) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableAuthenticationEvents()) return;

            // Dedup: both failedToAuthenticate and failedToLogIn can fire for the same event
            String key = (username != null ? username : "UNKNOWN");
            long now = System.currentTimeMillis();
            Long last = lastFailedLoginTime.get(key);
            if (last != null && (now - last) < FAILED_LOGIN_DEDUP_MS) return;
            lastFailedLoginTime.put(key, now);

            String ip = extractIp();
            AuditLogEntry entry = AuditLogEntry.withAuth(
                    username != null ? username : "UNKNOWN", "FAILED_LOGIN", "Jenkins",
                    String.format("Authentication failed for user '%s' from IP %s",
                            username != null ? username : "UNKNOWN", ip),
                    ip, "failed");
            entry.setSeverity("CRITICAL");
            AuditLogStorage.getInstance().addEntry(entry);
            LOGGER.log(Level.WARNING, "Login FAILED: user={0} ip={1}", new Object[]{username, ip});
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error recording auth failure", e);
        }
    }

    @Override
    protected void loggedOut(String username) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableAuthenticationEvents()) return;
            if (!isRealUser(username)) return;

            String ip = extractIp();
            AuditLogEntry entry = AuditLogEntry.withAuth(
                    username, "LOGOUT", "Jenkins",
                    String.format("User '%s' logged out", username), ip, "session");
            AuditLogStorage.getInstance().addEntry(entry);
            LOGGER.log(Level.INFO, "Logout: user={0} ip={1}", new Object[]{username, ip});
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error recording logout event", e);
        }
    }

    // --- Helpers ---

    private static boolean isApiAuthentication(String authMethod) {
        return "basic-auth".equals(authMethod) || "bearer-token".equals(authMethod)
                || "api-token".equals(authMethod) || "reverse-proxy-sso".equals(authMethod);
    }

    private static boolean isSsoAuthentication(String authMethod) {
        switch (authMethod) {
            case "saml2":
            case "oauth2":
            case "oidc":
            case "github-oauth":
            case "gitlab-oauth":
            case "google-oauth":
            case "azure-ad":
            case "bitbucket-oauth":
            case "crowd-sso":
            case "cas-sso":
            case "kerberos-spnego":
            case "ldap":
                return true;
            default:
                return false;
        }
    }

    private void evictStaleDedup(long now) {
        if (lastApiAuthTime.size() > MAX_DEDUP_ENTRIES) {
            long cutoff = now - API_AUTH_DEDUP_MS * 2;
            Iterator<Map.Entry<String, Long>> it = lastApiAuthTime.entrySet().iterator();
            while (it.hasNext()) {
                if (it.next().getValue() < cutoff) it.remove();
            }
        }
    }

    private static HttpServletRequest getRequest() {
        // 1. RequestHolder — set by AuditRequestCapture filter (may be null during
        //    authenticated2() because PluginServletFilter runs AFTER HudsonFilter/security chain)
        HttpServletRequest req = RequestHolder.get();
        if (req != null) return req;

        // 2. Stapler — set by the Stapler servlet (also runs after security chain)
        try {
            StaplerRequest2 sr = Stapler.getCurrentRequest2();
            if (sr != null) return sr;
        } catch (RuntimeException ignored) {}

        // 3. Spring's RequestContextHolder — populated by RequestContextHolderAwareRequestFilter
        //    early in the Spring Security chain, BEFORE UsernamePasswordAuthenticationFilter.
        //    This is the most reliable source during authenticated2() for form logins.
        try {
            Class<?> rch = Class.forName(
                    "org.springframework.web.context.request.RequestContextHolder",
                    false, jenkins.model.Jenkins.class.getClassLoader());
            java.lang.reflect.Method getAttrs = rch.getMethod("getRequestAttributes");
            Object attrs = getAttrs.invoke(null);
            if (attrs != null) {
                java.lang.reflect.Method getReq = attrs.getClass().getMethod("getRequest");
                Object reqObj = getReq.invoke(attrs);
                if (reqObj instanceof HttpServletRequest) {
                    return (HttpServletRequest) reqObj;
                }
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}

        // 4. Jetty thread-local HttpConnection — bound to the request thread by Winstone
        //    before any filter runs, so it works even when step 1-3 fail.
        return getJettyRequest();
    }

    // --- Cached Jetty reflection handles (resolved once, reused forever) ---
    private static volatile boolean jettyResolved = false;
    private static volatile java.lang.reflect.Method jettyGetCurrentConnection;
    private static volatile java.lang.reflect.Method jettyGetHttpChannel;  // on connection
    private static volatile java.lang.reflect.Method jettyGetRequest;       // on channel

    /** Pulls the current HttpServletRequest from Jetty's thread-local HttpConnection. */
    private static HttpServletRequest getJettyRequest() {
        if (!jettyResolved) resolveJettyMethods();
        if (jettyGetCurrentConnection == null) return null;
        try {
            Object conn = jettyGetCurrentConnection.invoke(null);
            if (conn == null) return null;
            if (jettyGetHttpChannel != null) {
                Object channel = jettyGetHttpChannel.invoke(conn);
                if (channel != null && jettyGetRequest != null) {
                    Object reqObj = jettyGetRequest.invoke(channel);
                    if (reqObj instanceof HttpServletRequest) return (HttpServletRequest) reqObj;
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINEST, "Jetty request extraction failed", e);
        }
        return null;
    }

    /** One-time resolution of Jetty method handles. Thread-safe. */
    private static synchronized void resolveJettyMethods() {
        if (jettyResolved) return;
        try {
            ClassLoader[] loaders = {
                    Thread.currentThread().getContextClassLoader(),
                    jenkins.model.Jenkins.class.getClassLoader(),
                    ClassLoader.getSystemClassLoader()
            };
            for (ClassLoader cl : loaders) {
                if (cl == null) continue;
                try {
                    Class<?> connCls = cl.loadClass("org.eclipse.jetty.server.HttpConnection");
                    jettyGetCurrentConnection = connCls.getMethod("getCurrentConnection");

                    // Resolve HttpChannel from a live connection if one exists, otherwise by class lookup
                    Object testConn = jettyGetCurrentConnection.invoke(null);
                    Class<?> channelCls;
                    if (testConn != null) {
                        channelCls = testConn.getClass().getMethod("getHttpChannel").invoke(testConn).getClass();
                        jettyGetHttpChannel = testConn.getClass().getMethod("getHttpChannel");
                    } else {
                        // No active connection — resolve from class hierarchy
                        jettyGetHttpChannel = connCls.getMethod("getHttpChannel");
                        channelCls = cl.loadClass("org.eclipse.jetty.server.HttpChannel");
                    }
                    jettyGetRequest = channelCls.getMethod("getRequest");
                    LOGGER.fine("Jetty reflection resolved");
                    break;
                } catch (ClassNotFoundException ignored) {
                } catch (Exception e) {
                    LOGGER.log(Level.FINE, "Jetty reflection failed with CL " + cl, e);
                    break;
                }
            }
        } finally {
            jettyResolved = true;
        }
    }

    private static String extractIp() {
        // 1. Spring Security WebAuthenticationDetails (available during auth processing)
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getDetails() instanceof WebAuthenticationDetails) {
                String ip = ((WebAuthenticationDetails) auth.getDetails()).getRemoteAddress();
                if (ip != null && !ip.isEmpty()) return ip;
            }
        } catch (Exception ignored) {}

        // 2. HttpServletRequest (via RequestHolder or Stapler)
        try {
            HttpServletRequest req = getRequest();
            if (req != null) {
                String xff = req.getHeader("X-Forwarded-For");
                if (xff != null && !xff.isEmpty()) return xff.split(",")[0].trim();
                String xRealIp = req.getHeader("X-Real-IP");
                if (xRealIp != null && !xRealIp.isEmpty()) return xRealIp.trim();
                return req.getRemoteAddr();
            }
        } catch (Exception ignored) {}

        // 3. Jetty thread name: "Handling GET /path from [ip] : Jetty (winstone)-N"
        try {
            String threadName = Thread.currentThread().getName();
            if (threadName.contains(" from ")) {
                int fromIdx = threadName.lastIndexOf(" from ") + 6;
                String ipPart = threadName.substring(fromIdx).trim();
                int colonIdx = ipPart.indexOf(" : ");
                if (colonIdx > 0) ipPart = ipPart.substring(0, colonIdx).trim();
                if (ipPart.startsWith("[") && ipPart.endsWith("]")) {
                    ipPart = ipPart.substring(1, ipPart.length() - 1);
                }
                if (!ipPart.isEmpty()) return ipPart;
            }
        } catch (Exception ignored) {}

        return "N/A";
    }

    private static String extractSessionId() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getDetails() instanceof WebAuthenticationDetails) {
                String sid = ((WebAuthenticationDetails) auth.getDetails()).getSessionId();
                if (sid != null && !sid.isEmpty()) return sid;
            }
        } catch (Exception ignored) {}
        try {
            HttpServletRequest req = getRequest();
            if (req != null && req.getSession(false) != null) {
                return req.getSession(false).getId();
            }
        } catch (Exception ignored) {}
        return "N/A";
    }

    private static String extractUserAgent() {
        try {
            HttpServletRequest req = getRequest();
            if (req != null) {
                String ua = req.getHeader("User-Agent");
                return ua != null ? ua : "N/A";
            }
        } catch (Exception ignored) {}
        return "N/A";
    }

    private static String detectAuthMethod() {
        // 1. Check HTTP request for protocol-level indicators (most reliable signal)
        //    The request IS always on the thread during authenticated2(), but we need
        //    Jetty's classloader to access it.
        try {
            HttpServletRequest req = getRequest();
            if (req != null) {
                // Authorization header — definitive signal for basic/bearer/kerberos
                String authHeader = req.getHeader("Authorization");
                if (authHeader != null) {
                    if (authHeader.regionMatches(true, 0, "Basic ", 0, 6)) return "basic-auth";
                    if (authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) return "bearer-token";
                    if (authHeader.regionMatches(true, 0, "Negotiate ", 0, 10)) return "kerberos-spnego";
                    if (authHeader.regionMatches(true, 0, "NTLM ", 0, 5)) return "ntlm";
                }

                // Jenkins API token header (used by Jenkins CLI and some integrations)
                if (req.getHeader("Jenkins-API-Token") != null) return "api-token";

                // SSO callback URL paths
                String uri = req.getRequestURI();
                if (uri != null) {
                    if (uri.contains("/saml/") || uri.contains("/SAML/")) return "saml2";
                    if (uri.contains("/securityRealm/finishLogin")) {
                        if (hasSamlIndicator(req)) return "saml2";
                        // finishLogin is the OAuth/OIDC callback — classify by realm
                        return classifyByRealmOrDefault("sso-callback");
                    }
                    // j_spring_security_check is the classic form login POST
                    if (uri.contains("/j_spring_security_check")) return "form";
                }

                // SAML-specific: SAMLResponse POST parameter
                if ("POST".equalsIgnoreCase(req.getMethod())) {
                    String ct = req.getContentType();
                    if (ct != null && ct.contains("form") && req.getParameter("SAMLResponse") != null) {
                        return "saml2";
                    }
                }

                // Reverse-proxy SSO headers
                String xAuth = req.getHeader("X-Auth-Request-User");
                if (xAuth != null && !xAuth.isEmpty()) return "reverse-proxy-sso";
                String xForwarded = req.getHeader("X-Forwarded-User");
                if (xForwarded != null && !xForwarded.isEmpty()) return "reverse-proxy-sso";

                // If we have the request but no Authorization header and no SSO indicator,
                // it's a session-based request (user already authenticated, session cookie sent)
                if (authHeader == null && req.getSession(false) != null) {
                    return classifyByRealmOrDefault("session");
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINEST, "Request-based auth detection failed", e);
        }

        // 2. Thread name URL-based detection — most reliable when HTTP request is unavailable.
        //    Jetty thread names: "Handling POST /j_spring_security_check from [ip] : ..."
        //    Must run BEFORE auth token classification because UsernamePasswordAuthenticationToken
        //    is used for both form logins and basic-auth, making token type ambiguous.
        String threadAuth = detectAuthFromThreadName();
        if (threadAuth != null) return threadAuth;

        // 3. Inspect Spring Security Authentication token type
        //    NOTE: During authenticated2(), SecurityContext may NOT be populated yet.
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                String method = classifyAuthToken(auth);
                if (method != null) return method;
            }
        } catch (Exception ignored) {}

        // 4. Check Jenkins SecurityRealm class to infer auth method (last resort)
        return classifyByRealmOrDefault("unknown");
    }

    /**
     * Classify auth method from SecurityRealm, falling back to the given default.
     */
    private static String classifyByRealmOrDefault(String fallback) {
        try {
            jenkins.model.Jenkins j = jenkins.model.Jenkins.getInstanceOrNull();
            if (j != null) {
                String realmClass = j.getSecurityRealm().getClass().getName().toLowerCase();
                String realmMethod = classifySecurityRealm(realmClass);
                if (realmMethod != null) return realmMethod;
            }
        } catch (Exception ignored) {}
        return fallback;
    }

    /**
     * Classify auth method from the Spring Security Authentication token class hierarchy.
     * SSO plugins (SAML, OAuth, OIDC, LDAP, Kerberos) each produce distinct token types.
     */
    private static String classifyAuthToken(Authentication auth) {
        // Walk the class hierarchy and all interfaces to match known token types
        String fullName = auth.getClass().getName().toLowerCase();

        // SAML 2.0 (jenkins-saml-plugin, spring-security-saml2, keycloak-saml)
        if (fullName.contains("saml")) return "saml2";

        // OAuth 2.0 / OIDC (oic-auth, github-oauth, gitlab-oauth, azure-ad, google-login)
        if (fullName.contains("oauth2") || fullName.contains("oauth")) return "oauth2";
        if (fullName.contains("oidc") || fullName.contains("openid") || fullName.contains("oic")) return "oidc";

        // Specific SSO plugins
        if (fullName.contains("github")) return "github-oauth";
        if (fullName.contains("gitlab")) return "gitlab-oauth";
        if (fullName.contains("google")) return "google-oauth";
        if (fullName.contains("azuread") || fullName.contains("azure")) return "azure-ad";
        if (fullName.contains("bitbucket")) return "bitbucket-oauth";
        if (fullName.contains("crowd") || fullName.contains("atlassian")) return "crowd-sso";
        if (fullName.contains("cas")) return "cas-sso";

        // Kerberos / SPNEGO
        if (fullName.contains("kerberos") || fullName.contains("spnego")) return "kerberos-spnego";

        // LDAP (often UsernamePasswordAuthenticationToken but from LDAP provider)
        if (fullName.contains("ldap")) return "ldap";

        // API token (Jenkins built-in)
        if (fullName.contains("apitoken") || fullName.contains("api_token")) return "api-token";

        // Jenkins core token types
        String simpleName = auth.getClass().getSimpleName();
        // NOTE: UsernamePasswordAuthenticationToken is used for BOTH form login AND basic-auth.
        // Do NOT classify it here — let thread-name detection (earlier priority) handle the distinction.
        if (simpleName.contains("RememberMe")) return "remember-me";
        if (simpleName.contains("Anonymous")) return "anonymous";

        // Check auth.details for additional clues
        if (auth.getDetails() instanceof WebAuthenticationDetails) return "http-auth";

        return null;
    }

    /**
     * Infer auth method from the Jenkins SecurityRealm class when no better signal is available.
     * This catches LDAP, Active Directory, and SSO realms that use standard Spring tokens.
     */
    private static String classifySecurityRealm(String realmClass) {
        if (realmClass.contains("saml")) return "saml2";
        if (realmClass.contains("oic") || realmClass.contains("oidc") || realmClass.contains("openid")) return "oidc";
        if (realmClass.contains("oauth")) return "oauth2";
        if (realmClass.contains("github")) return "github-oauth";
        if (realmClass.contains("gitlab")) return "gitlab-oauth";
        if (realmClass.contains("google")) return "google-oauth";
        if (realmClass.contains("azure") || realmClass.contains("activedirectory")) return "azure-ad";
        if (realmClass.contains("ldap")) return "ldap";
        if (realmClass.contains("crowd") || realmClass.contains("atlassian")) return "crowd-sso";
        if (realmClass.contains("cas")) return "cas-sso";
        if (realmClass.contains("kerberos") || realmClass.contains("spnego")) return "kerberos-spnego";
        if (realmClass.contains("pam") || realmClass.contains("unix")) return "pam-unix";
        if (realmClass.contains("hudsonprivate") || realmClass.contains("jenkinsown")) return "jenkins-db";
        return null;
    }

    private static boolean hasSamlIndicator(HttpServletRequest req) {
        try {
            // Check for SAMLResponse or RelayState parameters typical of SAML SSO
            return req.getParameter("SAMLResponse") != null
                    || req.getParameter("SAMLart") != null
                    || req.getParameter("RelayState") != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Detect auth method from Jetty thread name when HTTP request is unavailable.
     * Thread format: "Handling METHOD /path from [ip] : Jetty (winstone)-N"
     */
    private static String detectAuthFromThreadName() {
        try {
            String threadName = Thread.currentThread().getName();
            int handlingIdx = threadName.indexOf("Handling ");
            if (handlingIdx < 0) return null;

            String after = threadName.substring(handlingIdx + 9);
            int methodEnd = after.indexOf(' ');
            if (methodEnd < 0) return null;

            String httpMethod = after.substring(0, methodEnd);
            int fromIdx = after.indexOf(" from ");
            if (fromIdx < 0) return null;

            String path = after.substring(methodEnd + 1, fromIdx).trim();

            // Form login: POST to /j_spring_security_check
            if ("POST".equals(httpMethod) && path.contains("/j_spring_security_check")) {
                return "form";
            }
            // SSO callbacks
            if (path.contains("/securityRealm/finishLogin")) return "sso-callback";
            if (path.contains("/saml/") || path.contains("/SAML/")) return "saml2";

            // API/CLI paths — authenticated via basic-auth or API token
            if (path.startsWith("/api/") || path.contains("/api/")
                    || path.endsWith("/build") || path.endsWith("/buildWithParameters")
                    || path.startsWith("/cli") || path.contains("/crumbIssuer")
                    || path.contains("/createItem") || path.contains("/doDelete")) {
                return "api-token";
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static boolean isRealUser(String username) {
        return username != null && !username.isEmpty()
                && !"anonymousUser".equals(username)
                && !"anonymous".equalsIgnoreCase(username)
                && !"system".equalsIgnoreCase(username);
    }

    static String buildAuthenticationDetail(String authMethod, String userAgent,
                                            boolean isApiAuth, boolean isSsoAuth) {
        String normalizedUserAgent = AuditUserAgentFormatter.normalizeForDetails(userAgent);
        if (isApiAuth) {
            return String.format("API authentication via %s (UA: %s)", authMethod, normalizedUserAgent);
        }
        if (isSsoAuth) {
            return String.format("SSO login via %s (UA: %s)", authMethod, normalizedUserAgent);
        }
        return String.format("Authenticated (method: %s, UA: %s)", authMethod, normalizedUserAgent);
    }
}
