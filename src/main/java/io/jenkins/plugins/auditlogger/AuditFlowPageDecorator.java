package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.PageDecorator;
import jenkins.model.Jenkins;
import java.util.List;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.verb.POST;

/**
 * Global PageDecorator extension that injects a security anomaly alert banner
 * into Jenkins page headers when active un-dismissed anomalies are detected.
 */
@Extension
public class AuditFlowPageDecorator extends PageDecorator {

    public AuditFlowPageDecorator() {
        super();
    }

    /**
     * Checks whether the anomaly alert banner should be displayed.
     * Returns true if master anomaly detection and banner toggles are enabled and there is at least one active alert.
     */
    public boolean isBannerVisible() {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && (!config.isEnableAnomalyDetection() || !config.isEnableAnomalyBanner())) {
                return false;
            }
            return getActiveAlertCount() > 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns current AuditFlow plugin release version.
     */
    public String getCurrentPluginVersion() {
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins != null && jenkins.getPluginManager() != null) {
                hudson.PluginWrapper plugin = jenkins.getPluginManager().getPlugin("auditflow");
                if (plugin == null) {
                    plugin = jenkins.getPluginManager().getPlugin("audit-logger");
                }
                if (plugin != null && plugin.getVersion() != null) {
                    return plugin.getVersion();
                }
            }
        } catch (Exception ignored) {}
        return "2.4.0";
    }

    /**
     * Checks whether the Welcome / Release Notes Banner should be displayed.
     * Automatically returns true on plugin updates until the user dismisses it for the current version.
     */
    public boolean isWelcomeBannerVisible() {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null) return false;
            String currentVersion = getCurrentPluginVersion();
            String dismissedVersion = config.getWelcomeBannerDismissedVersion();
            return !currentVersion.equalsIgnoreCase(dismissedVersion);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Stapler POST endpoint to dismiss the Welcome Banner for the current plugin release version.
     */
    @POST
    public HttpResponse doDismissWelcomeBanner() {
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins != null) {
                jenkins.checkPermission(Jenkins.READ);
            }
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null) {
                config.setWelcomeBannerDismissedVersion(getCurrentPluginVersion());
                config.save();
            }
        } catch (Exception ignored) {}
        return HttpResponses.ok();
    }

    /**
     * Checks if current user has Jenkins Administer permission.
     */
    public boolean isAdminUser() {
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            return jenkins != null && jenkins.hasPermission(Jenkins.ADMINISTER);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns the count of active, un-dismissed anomaly alerts.
     */
    public int getActiveAlertCount() {
        try {
            AuditLogStorage storage = AuditLogStorage.getInstance();
            if (storage == null) return 0;
            AnomalyDetector detector = storage.getAnomalyDetector();
            if (detector == null) return 0;
            List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(100);
            return alerts != null ? alerts.size() : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Returns the highest severity among active alerts (e.g. CRITICAL, HIGH, MEDIUM, LOW).
     */
    public String getHighestSeverity() {
        try {
            AuditLogStorage storage = AuditLogStorage.getInstance();
            if (storage == null) return "HIGH";
            AnomalyDetector detector = storage.getAnomalyDetector();
            if (detector == null) return "HIGH";
            List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(100);
            if (alerts == null || alerts.isEmpty()) return "HIGH";

            boolean hasCritical = alerts.stream().anyMatch(a -> "CRITICAL".equalsIgnoreCase(a.severity));
            if (hasCritical) return "CRITICAL";

            boolean hasHigh = alerts.stream().anyMatch(a -> "HIGH".equalsIgnoreCase(a.severity));
            if (hasHigh) return "HIGH";

            boolean hasMedium = alerts.stream().anyMatch(a -> "MEDIUM".equalsIgnoreCase(a.severity));
            if (hasMedium) return "MEDIUM";

            return "LOW";
        } catch (Exception e) {
            return "HIGH";
        }
    }

    /**
     * Returns the root-relative path to the AuditFlow dashboard.
     */
    public String getAuditFlowUrl() {
        try {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins != null) {
                String root = jenkins.getRootUrl();
                if (root != null && !root.isEmpty()) {
                    return root.endsWith("/") ? root + "manage/auditflow-logs/" : root + "/manage/auditflow-logs/";
                }
            }
        } catch (Exception ignored) {}
        return "/jenkins/manage/auditflow-logs/";
    }
}
