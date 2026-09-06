package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.PageDecorator;
import jenkins.model.Jenkins;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Global PageDecorator extension that injects a security anomaly alert banner
 * into Jenkins page headers when active un-dismissed anomalies for enabled rules are detected.
 */
@Extension
public class AuditFlowPageDecorator extends PageDecorator {

    public AuditFlowPageDecorator() {
        super();
    }

    /**
     * Checks whether the anomaly alert banner should be displayed.
     * Returns true if master anomaly detection, banner display, and at least one anomaly rule is enabled and there is at least one active alert.
     */
    public boolean isBannerVisible() {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null || !config.isEnableAnomalyDetection() || !config.isEnableAnomalyBanner() || !config.isAnyAnomalyRuleEnabled()) {
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
     * Returns the count of active, un-dismissed anomaly alerts for enabled rules.
     */
    public int getActiveAlertCount() {
        try {
            AuditLogStorage storage = AuditLogStorage.getInstance();
            if (storage == null) return 0;
            AnomalyDetector detector = storage.getAnomalyDetector();
            if (detector == null) return 0;
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null || !config.isEnableAnomalyDetection() || !config.isEnableAnomalyBanner() || !config.isAnyAnomalyRuleEnabled()) {
                return 0;
            }
            List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(100, config);
            return alerts != null ? alerts.size() : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Returns a human-readable comma-separated summary of the active anomaly types detected.
     */
    public String getActiveAlertTypesSummary() {
        try {
            AuditLogStorage storage = AuditLogStorage.getInstance();
            if (storage == null) return "";
            AnomalyDetector detector = storage.getAnomalyDetector();
            if (detector == null) return "";
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null || !config.isEnableAnomalyDetection() || !config.isEnableAnomalyBanner() || !config.isAnyAnomalyRuleEnabled()) {
                return "";
            }
            List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(100, config);
            if (alerts == null || alerts.isEmpty()) return "";

            Set<String> typeNames = new LinkedHashSet<>();
            for (AnomalyDetector.AnomalyAlert alert : alerts) {
                if (alert != null && alert.type != null) {
                    typeNames.add(formatAnomalyTypeName(alert.type));
                }
            }
            return String.join(", ", typeNames);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Returns a friendly display name for an anomaly type.
     */
    public static String formatAnomalyTypeName(AnomalyDetector.AnomalyType type) {
        if (type == null) return "Security Anomaly";
        switch (type) {
            case BRUTE_FORCE_LOGIN:
                return "Brute Force Login";
            case UNUSUAL_IP:
                return "Unusual IP Activity";
            case MULTI_IP_LOGIN:
                return "Multi-IP Logins";
            case SUSPICIOUS_AUTH_PATTERN:
                return "Suspicious Authentication";
            case ADMIN_PRIVILEGE_CHANGE:
                return "Admin Privilege Escalation";
            case USER_LIFECYCLE_ANOMALY:
                return "User Account Lifecycle Activity";
            case MASS_CHANGES:
                return "Mass Configuration Changes";
            case AFTER_HOURS_ADMIN:
                return "Off-Hours Admin Activity";
            case CREDENTIAL_EXPOSURE:
                return "Credential Exposure";
            default:
                return type.name().replace('_', ' ');
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
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null || !config.isEnableAnomalyDetection() || !config.isEnableAnomalyBanner() || !config.isAnyAnomalyRuleEnabled()) {
                return "HIGH";
            }
            List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(100, config);
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
