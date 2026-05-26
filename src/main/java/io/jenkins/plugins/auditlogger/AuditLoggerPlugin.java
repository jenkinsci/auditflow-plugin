package io.jenkins.plugins.auditlogger;

import hudson.Plugin;
import hudson.init.InitMilestone;
import hudson.init.Initializer;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Main plugin lifecycle class. Initializes and shuts down the audit logging system.
 */
public class AuditLoggerPlugin extends Plugin {
    private static final Logger LOGGER = Logger.getLogger(AuditLoggerPlugin.class.getName());

    @Override
    public void start() {
        LOGGER.info("Jenkins Audit Logger Plugin starting");

        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        if (config != null && config.getStartupGracePeriodSeconds() > 0) {
            StartupPhaseManager.setGracePeriodSeconds(config.getStartupGracePeriodSeconds());
        }

        StartupPhaseManager.initStartupTracking();
        AuditLogStorage.getInstance().initialize();
        AuditSaveableListener.primeCredentialCaches();

        if (config != null) {
            LOGGER.info("Audit Logger configured: Auth=" + config.isEnableAuthenticationEvents()
                    + " Build=" + config.isEnableBuildEvents()
                    + " JobConfig=" + config.isEnableJobConfigEvents()
                    + " GracePeriod=" + config.getStartupGracePeriodSeconds() + "s");
        }
    }

    @Override
    public void stop() {
        LOGGER.info("Jenkins Audit Logger Plugin stopping — flushing writes...");
        AuditLogStorage.getInstance().shutdown();
        LOGGER.info("Jenkins Audit Logger Plugin stopped");
    }

    @Initializer(after = InitMilestone.STARTED)
    public static void init() {
        // Ensure storage is ready before any listener fires
        AuditLogStorage.getInstance();
    }

    @Initializer(after = InitMilestone.JOB_LOADED)
    public static void primeCredentialCaches() {
        AuditSaveableListener.primeCredentialCaches();
    }

    /**
     * Wire into Spring Security's authentication failure path.
     * Jenkins 2.x + Spring Security 6 uses NullEventPublisher, so SecurityListener
     * callbacks don't fire for form login failures. We wrap the existing
     * AuthenticationFailureHandler via reflection (to bridge javax/jakarta mismatch)
     * to also fire SecurityListener.fireFailedToAuthenticate().
     */
    @Initializer(after = InitMilestone.JOB_LOADED)
    public static void installAuthFailureHandler() {
        try {
            jenkins.model.Jenkins j = jenkins.model.Jenkins.get();
            var servletContext = j.getServletContext();

            // Get HudsonFilter -> ChainedServletFilter2 -> filters array
            if (servletContext == null) { LOGGER.warning("ServletContext not available"); return; }
            Object hf = servletContext.getAttribute("hudson.security.HudsonFilter");
            if (hf == null) { LOGGER.warning("HudsonFilter not found"); return; }

            java.lang.reflect.Field filterField = hudson.security.HudsonFilter.class.getDeclaredField("filter");
            filterField.setAccessible(true);
            Object chainedFilter = filterField.get(hf);
            if (chainedFilter == null) { LOGGER.warning("ChainedServletFilter2 not found"); return; }

            java.lang.reflect.Field filtersField = chainedFilter.getClass().getDeclaredField("filters");
            filtersField.setAccessible(true);
            Object[] filters = (Object[]) filtersField.get(chainedFilter);

            for (Object filter : filters) {
                if (filter instanceof org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter) {
                    org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter authFilter =
                            (org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter) filter;

                    // Get current failure handler via reflection (it implements jakarta.servlet interface)
                    java.lang.reflect.Field fhField = org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter.class
                            .getDeclaredField("failureHandler");
                    fhField.setAccessible(true);
                    Object originalHandler = fhField.get(authFilter);

                    // Load the jakarta interface from the classloader that has it
                    ClassLoader jakartaLoader = originalHandler.getClass().getClassLoader();
                    Class<?> handlerInterface = jakartaLoader.loadClass(
                            "org.springframework.security.web.authentication.AuthenticationFailureHandler");

                    // Create a dynamic proxy that implements the jakarta version of the interface
                    Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                            jakartaLoader,
                            new Class<?>[]{handlerInterface},
                            (proxyObj, method, args) -> {
                                if ("onAuthenticationFailure".equals(method.getName()) && args != null && args.length == 3) {
                                    // args[0] = jakarta.servlet.http.HttpServletRequest
                                    // args[2] = AuthenticationException
                                    // Extract j_username from the request via reflection
                                    try {
                                        java.lang.reflect.Method getParam = args[0].getClass().getMethod("getParameter", String.class);
                                        String username = (String) getParam.invoke(args[0], "j_username");
                                        if (username != null && !username.isEmpty()) {
                                            jenkins.security.SecurityListener.fireFailedToAuthenticate(username);
                                        }
                                    } catch (Exception ex) {
                                        LOGGER.log(Level.FINE, "Failed to extract username from request", ex);
                                    }
                                    // Delegate to original handler
                                    return method.invoke(originalHandler, args);
                                }
                                return method.invoke(originalHandler, args);
                            });

                    // Set the proxy as the new failure handler
                    fhField.set(authFilter, proxy);
                    LOGGER.info("Wrapped AuthenticationFailureHandler on " + filter.getClass().getSimpleName());
                    break;
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not install auth failure handler wrapper", e);
        }
    }
}
