package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.PageDecorator;
import jenkins.model.Jenkins;
import java.util.List;

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
     * Returns true if there is at least one active, un-dismissed anomaly alert.
     */
    public boolean isBannerVisible() {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableAnomalyBanner()) {
                return false;
            }
            return getActiveAlertCount() > 0;
        } catch (Exception e) {
            return false;
        }
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
