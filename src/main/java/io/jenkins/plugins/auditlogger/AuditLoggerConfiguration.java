package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.BulkChange;
import hudson.model.Descriptor;
import hudson.util.ListBoxModel;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest2;

import java.io.IOException;
import java.time.Instant;
import java.time.DateTimeException;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Global configuration for Jenkins Audit Logger plugin.
 * Manage Jenkins -> Configure System -> Audit Logger
 */
@Extension
public class AuditLoggerConfiguration extends GlobalConfiguration {
    private static final Logger LOGGER = Logger.getLogger(AuditLoggerConfiguration.class.getName());
    private static final String DEFAULT_DISPLAY_TIME_ZONE = "UTC";
    private static final List<String> AVAILABLE_DISPLAY_TIME_ZONES = List.of(
            "Asia/Kolkata",
            "Europe/London",
        "America/New_York",
        DEFAULT_DISPLAY_TIME_ZONE);

    // Event Categories
    private boolean enableAuthenticationEvents = true;
    private boolean enableBuildEvents = true;
    private boolean enableJobConfigEvents = true;
    private boolean enablePipelineEvents = true;
    private boolean enableCredentialEvents = true;
    private boolean enablePluginEvents = true;
    private boolean enableSystemConfigEvents = false;
    private boolean enableNodeEvents = false;
    private boolean enableApiEvents = false;

    // Risk Detection — temporarily disabled to keep the write path lightweight.
    private boolean anomalyFailedLogins = false;
    private int anomalyFailedLoginsThreshold = 5;
    private int anomalyFailedLoginsWindowMinutes = 15;

    private boolean anomalyCredentialChanges = false;
    private int anomalyCredentialChangesThreshold = 3;

    private boolean anomalyPluginChanges = false;
    private int anomalyPluginChangesThreshold = 3;

    private boolean anomalyGlobalConfigChanges = false;
    private int anomalyGlobalConfigChangesThreshold = 5;

    private boolean anomalyJobConfigChanges = false;
    private int anomalyJobConfigChangesThreshold = 1;
    private String anomalyWatchedJobPatterns = "";

    private boolean anomalySecurityConfigChanges = false;
    private int anomalySecurityConfigChangesThreshold = 1;

    private boolean anomalyOffHoursAdmin = false;

    private boolean anomalyBuildFailures = false;
    private int anomalyBuildFailuresThreshold = 5;

    // Backward-compat aliases (kept for code that still reads old names)
    private boolean enableFailedLoginDetection = true;
    private int failedLoginThreshold = 5;
    private int failedLoginTimeWindowMinutes = 15;
    private boolean enableProductionJobChangeAlert = true;
    private boolean enableCredentialUpdateAlert = true;
    private boolean enablePluginInstallAlert = true;
    private boolean enableAdminOffHoursAlert = false;

    // Log Retention
    private int logRetentionDays = 90;
    private int maxLogFileSizeMB = 50;
    private boolean enableLogRotation = true;

    // Startup
    private int startupGracePeriodSeconds = 120;

    // Optimization
    private boolean enableAdvancedIndexing = false;
    private boolean enableAnomalyDetection = false;
    private boolean enableMetricsCollection = false;
    private int batchWriteSize = 100;
    private int batchFlushIntervalSeconds = 5;

    // Privacy
    private boolean maskTokens = true;
    private boolean maskEmailAddresses = false;
    private boolean maskCreditCards = true;

    // Alerts
    private boolean enableAlertEngine = false;
    private boolean enableComplianceReports = false;

    // UI
    private boolean enableRiskLevels = true;
    private boolean enableEventCategories = false;
    private boolean enableTimelineView = false;
    private boolean enableSensitiveEventsPanel = false;
    private boolean enableDashboardMetrics = false;
    private boolean enableDashboardStats = true;
    private boolean enableAnomalyRow = false;
    private String displayTimeZoneId = "UTC";
    private boolean showMetricTotal = true;
    private boolean showMetricLogins = true;
    private boolean showMetricFailedLogins = true;
    private boolean showMetricBuilds = true;
    private boolean showMetricJobs = true;
    private boolean showMetricConfig = true;

    // Export
    private boolean enableCsvExport = true;
    private boolean enableJsonExport = true;
    private boolean enablePdfExport = false;

    // REST API
    private boolean enableAuditApi = true;

    public AuditLoggerConfiguration() {
        load();
        displayTimeZoneId = sanitizeTimeZoneId(displayTimeZoneId);
    }

    public static AuditLoggerConfiguration get() {
        return GlobalConfiguration.all().get(AuditLoggerConfiguration.class);
    }

    @Override
    public boolean configure(StaplerRequest2 req, JSONObject json) throws Descriptor.FormException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        try (BulkChange bulkChange = new BulkChange(this)) {
            boolean configured;
            if (req == null) {
                applyJsonConfiguration(json);
                configured = true;
            } else {
                configured = super.configure(req, json);
            }
            StartupPhaseManager.setGracePeriodSeconds(startupGracePeriodSeconds);
            bulkChange.commit();
            return configured;
        } catch (IOException e) {
            LOGGER.warning("Failed to save AuditFlow configuration: " + e.getMessage());
            return false;
        }
    }

    private void applyJsonConfiguration(JSONObject json) {
        if (json == null) {
            return;
        }

        if (json.has("enableAuthenticationEvents")) setEnableAuthenticationEvents(json.optBoolean("enableAuthenticationEvents", enableAuthenticationEvents));
        if (json.has("enableBuildEvents")) setEnableBuildEvents(json.optBoolean("enableBuildEvents", enableBuildEvents));
        if (json.has("enableJobConfigEvents")) setEnableJobConfigEvents(json.optBoolean("enableJobConfigEvents", enableJobConfigEvents));
        if (json.has("enableCredentialEvents")) setEnableCredentialEvents(json.optBoolean("enableCredentialEvents", enableCredentialEvents));
        if (json.has("enablePluginEvents")) setEnablePluginEvents(json.optBoolean("enablePluginEvents", enablePluginEvents));
        if (json.has("enableSystemConfigEvents")) setEnableSystemConfigEvents(json.optBoolean("enableSystemConfigEvents", enableSystemConfigEvents));

        if (json.has("enableDashboardStats")) setEnableDashboardStats(json.optBoolean("enableDashboardStats", enableDashboardStats));
        if (json.has("enableRiskLevels")) setEnableRiskLevels(json.optBoolean("enableRiskLevels", enableRiskLevels));
        if (json.has("displayTimeZoneId")) setDisplayTimeZoneId(json.optString("displayTimeZoneId", displayTimeZoneId));
        if (json.has("showMetricTotal")) setShowMetricTotal(json.optBoolean("showMetricTotal", showMetricTotal));
        if (json.has("showMetricLogins")) setShowMetricLogins(json.optBoolean("showMetricLogins", showMetricLogins));
        if (json.has("showMetricFailedLogins")) setShowMetricFailedLogins(json.optBoolean("showMetricFailedLogins", showMetricFailedLogins));
        if (json.has("showMetricBuilds")) setShowMetricBuilds(json.optBoolean("showMetricBuilds", showMetricBuilds));
        if (json.has("showMetricJobs")) setShowMetricJobs(json.optBoolean("showMetricJobs", showMetricJobs));
        if (json.has("showMetricConfig")) setShowMetricConfig(json.optBoolean("showMetricConfig", showMetricConfig));

        if (json.has("enableCsvExport")) setEnableCsvExport(json.optBoolean("enableCsvExport", enableCsvExport));
        if (json.has("enableJsonExport")) setEnableJsonExport(json.optBoolean("enableJsonExport", enableJsonExport));
        if (json.has("enableAuditApi")) setEnableAuditApi(json.optBoolean("enableAuditApi", enableAuditApi));

        if (json.has("logRetentionDays")) setLogRetentionDays(json.optInt("logRetentionDays", logRetentionDays));
        if (json.has("maxLogFileSizeMB")) setMaxLogFileSizeMB(json.optInt("maxLogFileSizeMB", maxLogFileSizeMB));
        if (json.has("enableLogRotation")) setEnableLogRotation(json.optBoolean("enableLogRotation", enableLogRotation));
        if (json.has("startupGracePeriodSeconds")) setStartupGracePeriodSeconds(json.optInt("startupGracePeriodSeconds", startupGracePeriodSeconds));
        if (json.has("batchWriteSize")) setBatchWriteSize(json.optInt("batchWriteSize", batchWriteSize));
        if (json.has("batchFlushIntervalSeconds")) setBatchFlushIntervalSeconds(json.optInt("batchFlushIntervalSeconds", batchFlushIntervalSeconds));

        if (json.has("maskTokens")) setMaskTokens(json.optBoolean("maskTokens", maskTokens));
        if (json.has("maskEmailAddresses")) setMaskEmailAddresses(json.optBoolean("maskEmailAddresses", maskEmailAddresses));
        if (json.has("maskCreditCards")) setMaskCreditCards(json.optBoolean("maskCreditCards", maskCreditCards));
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private static String sanitizeTimeZoneId(String value) {
        if (value == null || value.trim().isEmpty()) {
            return DEFAULT_DISPLAY_TIME_ZONE;
        }

        String candidate = value.trim();
        try {
            String normalized = ZoneId.of(candidate).getId();
            return AVAILABLE_DISPLAY_TIME_ZONES.contains(normalized)
                    ? normalized
                    : DEFAULT_DISPLAY_TIME_ZONE;
        } catch (DateTimeException ignored) {
            return DEFAULT_DISPLAY_TIME_ZONE;
        }
    }

    @DataBoundSetter
    public void setEnableAuthenticationEvents(boolean enableAuthenticationEvents) {
        this.enableAuthenticationEvents = enableAuthenticationEvents;
        save();
    }

    @DataBoundSetter
    public void setEnableBuildEvents(boolean enableBuildEvents) {
        this.enableBuildEvents = enableBuildEvents;
        save();
    }

    @DataBoundSetter
    public void setEnableJobConfigEvents(boolean enableJobConfigEvents) {
        this.enableJobConfigEvents = enableJobConfigEvents;
        save();
    }

    @DataBoundSetter
    public void setEnableCredentialEvents(boolean enableCredentialEvents) {
        this.enableCredentialEvents = enableCredentialEvents;
        save();
    }

    @DataBoundSetter
    public void setEnablePluginEvents(boolean enablePluginEvents) {
        this.enablePluginEvents = enablePluginEvents;
        save();
    }

    @DataBoundSetter
    public void setEnableSystemConfigEvents(boolean enableSystemConfigEvents) {
        this.enableSystemConfigEvents = enableSystemConfigEvents;
        save();
    }

    @DataBoundSetter
    public void setEnableDashboardStats(boolean enableDashboardStats) {
        this.enableDashboardStats = enableDashboardStats;
        save();
    }

    @DataBoundSetter
    public void setEnableRiskLevels(boolean enableRiskLevels) {
        this.enableRiskLevels = enableRiskLevels;
        save();
    }

    @DataBoundSetter
    public void setDisplayTimeZoneId(String displayTimeZoneId) {
        this.displayTimeZoneId = sanitizeTimeZoneId(displayTimeZoneId);
        save();
    }

    @DataBoundSetter
    public void setShowMetricTotal(boolean showMetricTotal) {
        this.showMetricTotal = showMetricTotal;
        save();
    }

    @DataBoundSetter
    public void setShowMetricLogins(boolean showMetricLogins) {
        this.showMetricLogins = showMetricLogins;
        save();
    }

    @DataBoundSetter
    public void setShowMetricFailedLogins(boolean showMetricFailedLogins) {
        this.showMetricFailedLogins = showMetricFailedLogins;
        save();
    }

    @DataBoundSetter
    public void setShowMetricBuilds(boolean showMetricBuilds) {
        this.showMetricBuilds = showMetricBuilds;
        save();
    }

    @DataBoundSetter
    public void setShowMetricJobs(boolean showMetricJobs) {
        this.showMetricJobs = showMetricJobs;
        save();
    }

    @DataBoundSetter
    public void setShowMetricConfig(boolean showMetricConfig) {
        this.showMetricConfig = showMetricConfig;
        save();
    }

    @DataBoundSetter
    public void setEnableCsvExport(boolean enableCsvExport) {
        this.enableCsvExport = enableCsvExport;
        save();
    }

    @DataBoundSetter
    public void setEnableJsonExport(boolean enableJsonExport) {
        this.enableJsonExport = enableJsonExport;
        save();
    }

    @DataBoundSetter
    public void setEnableAuditApi(boolean enableAuditApi) {
        this.enableAuditApi = enableAuditApi;
        save();
    }

    @DataBoundSetter
    public void setLogRetentionDays(int logRetentionDays) {
        this.logRetentionDays = clamp(logRetentionDays, 0, 3650);
        save();
    }

    @DataBoundSetter
    public void setMaxLogFileSizeMB(int maxLogFileSizeMB) {
        this.maxLogFileSizeMB = clamp(maxLogFileSizeMB, 1, 1024);
        save();
    }

    @DataBoundSetter
    public void setEnableLogRotation(boolean enableLogRotation) {
        this.enableLogRotation = enableLogRotation;
        save();
    }

    @DataBoundSetter
    public void setStartupGracePeriodSeconds(int startupGracePeriodSeconds) {
        this.startupGracePeriodSeconds = clamp(startupGracePeriodSeconds, 5, 300);
        StartupPhaseManager.setGracePeriodSeconds(this.startupGracePeriodSeconds);
        save();
    }

    @DataBoundSetter
    public void setBatchWriteSize(int batchWriteSize) {
        this.batchWriteSize = clamp(batchWriteSize, 1, 10000);
        save();
    }

    @DataBoundSetter
    public void setBatchFlushIntervalSeconds(int batchFlushIntervalSeconds) {
        this.batchFlushIntervalSeconds = clamp(batchFlushIntervalSeconds, 1, 300);
        save();
    }

    @DataBoundSetter
    public void setMaskTokens(boolean maskTokens) {
        this.maskTokens = maskTokens;
        save();
    }

    @DataBoundSetter
    public void setMaskEmailAddresses(boolean maskEmailAddresses) {
        this.maskEmailAddresses = maskEmailAddresses;
        save();
    }

    @DataBoundSetter
    public void setMaskCreditCards(boolean maskCreditCards) {
        this.maskCreditCards = maskCreditCards;
        save();
    }

    // --- Getters ---

    public boolean isEnableAuthenticationEvents() { return enableAuthenticationEvents; }
    public boolean isEnableBuildEvents() { return enableBuildEvents; }
    public boolean isEnableJobConfigEvents() { return enableJobConfigEvents; }
    public boolean isEnablePipelineEvents() { return enablePipelineEvents; }
    public boolean isEnableCredentialEvents() { return enableCredentialEvents; }
    public boolean isEnablePluginEvents() { return enablePluginEvents; }
    public boolean isEnableSystemConfigEvents() { return enableSystemConfigEvents; }
    public boolean isEnableNodeEvents() { return enableNodeEvents; }
    public boolean isEnableApiEvents() { return enableApiEvents; }

    public boolean isEnableFailedLoginDetection() { return enableFailedLoginDetection; }
    public int getFailedLoginThreshold() { return failedLoginThreshold; }
    public int getFailedLoginTimeWindowMinutes() { return failedLoginTimeWindowMinutes; }
    public boolean isEnableProductionJobChangeAlert() { return enableProductionJobChangeAlert; }
    public boolean isEnableCredentialUpdateAlert() { return enableCredentialUpdateAlert; }
    public boolean isEnablePluginInstallAlert() { return enablePluginInstallAlert; }

    // Anomaly Detection getters
    public boolean isAnomalyFailedLogins() { return anomalyFailedLogins; }
    public int getAnomalyFailedLoginsThreshold() { return anomalyFailedLoginsThreshold; }
    public int getAnomalyFailedLoginsWindowMinutes() { return anomalyFailedLoginsWindowMinutes; }
    public boolean isAnomalyCredentialChanges() { return anomalyCredentialChanges; }
    public int getAnomalyCredentialChangesThreshold() { return anomalyCredentialChangesThreshold; }
    public boolean isAnomalyPluginChanges() { return anomalyPluginChanges; }
    public int getAnomalyPluginChangesThreshold() { return anomalyPluginChangesThreshold; }
    public boolean isAnomalyGlobalConfigChanges() { return anomalyGlobalConfigChanges; }
    public int getAnomalyGlobalConfigChangesThreshold() { return anomalyGlobalConfigChangesThreshold; }
    public boolean isAnomalyJobConfigChanges() { return anomalyJobConfigChanges; }
    public int getAnomalyJobConfigChangesThreshold() { return anomalyJobConfigChangesThreshold; }
    public String getAnomalyWatchedJobPatterns() { return anomalyWatchedJobPatterns != null ? anomalyWatchedJobPatterns : ""; }
    public boolean isAnomalySecurityConfigChanges() { return anomalySecurityConfigChanges; }
    public int getAnomalySecurityConfigChangesThreshold() { return anomalySecurityConfigChangesThreshold; }
    public boolean isAnomalyOffHoursAdmin() { return anomalyOffHoursAdmin; }
    public boolean isAnomalyBuildFailures() { return anomalyBuildFailures; }
    public int getAnomalyBuildFailuresThreshold() { return anomalyBuildFailuresThreshold; }
    public boolean isEnableAdminOffHoursAlert() { return enableAdminOffHoursAlert; }

    public int getLogRetentionDays() { return logRetentionDays; }
    public int getMaxLogFileSizeMB() { return maxLogFileSizeMB; }
    public long getMaxLogFileSizeBytes() { return (long) maxLogFileSizeMB * 1024L * 1024L; }
    public boolean isEnableLogRotation() { return enableLogRotation; }

    public int getStartupGracePeriodSeconds() { return startupGracePeriodSeconds; }

    public boolean isEnableAdvancedIndexing() { return enableAdvancedIndexing; }
    public boolean isEnableAnomalyDetection() { return false; }
    public boolean isEnableMetricsCollection() { return enableMetricsCollection; }
    public int getBatchWriteSize() { return batchWriteSize; }
    public int getBatchFlushIntervalSeconds() { return batchFlushIntervalSeconds; }

    public boolean isMaskTokens() { return maskTokens; }
    public boolean isMaskEmailAddresses() { return maskEmailAddresses; }
    public boolean isMaskCreditCards() { return maskCreditCards; }

    public boolean isEnableAlertEngine() { return enableAlertEngine; }
    public boolean isEnableComplianceReports() { return enableComplianceReports; }

    public boolean isEnableRiskLevels() { return enableRiskLevels; }
    public boolean isEnableEventCategories() { return enableEventCategories; }
    public boolean isEnableTimelineView() { return enableTimelineView; }
    public boolean isEnableSensitiveEventsPanel() { return enableSensitiveEventsPanel; }
    public boolean isEnableDashboardMetrics() { return enableDashboardMetrics; }
    public boolean isEnableDashboardStats() { return enableDashboardStats; }
    public boolean isEnableAnomalyRow() { return false; }
    public String getDisplayTimeZoneId() { return sanitizeTimeZoneId(displayTimeZoneId); }
    public String getDisplayTimeZoneDisplayName() {
        return getDisplayTimeZoneId();
    }
    public ZoneId getDisplayTimeZone() {
        return ZoneId.of(getDisplayTimeZoneId());
    }
    public List<String> getAvailableDisplayTimeZoneIds() {
        return AVAILABLE_DISPLAY_TIME_ZONES;
    }
    public List<String> getPopularDisplayTimeZoneIds() {
        return AVAILABLE_DISPLAY_TIME_ZONES;
    }
    public String getAvailableDisplayTimeZonesJson() {
        return new com.google.gson.Gson().toJson(toDisplayTimeZoneOptions(AVAILABLE_DISPLAY_TIME_ZONES));
    }
    public String getPopularDisplayTimeZonesJson() {
        return getAvailableDisplayTimeZonesJson();
    }
    public ListBoxModel doFillDisplayTimeZoneIdItems() {
        ListBoxModel items = new ListBoxModel();
        String selectedTimeZone = getDisplayTimeZoneId();
        for (String timeZoneId : AVAILABLE_DISPLAY_TIME_ZONES) {
            items.add(new ListBoxModel.Option(
                    toDisplayTimeZoneLabel(timeZoneId),
                    timeZoneId,
                    timeZoneId.equals(selectedTimeZone)));
        }
        return items;
    }
    public boolean isShowMetricTotal() { return showMetricTotal; }
    public boolean isShowMetricLogins() { return showMetricLogins; }
    public boolean isShowMetricFailedLogins() { return showMetricFailedLogins; }
    public boolean isShowMetricBuilds() { return showMetricBuilds; }
    public boolean isShowMetricJobs() { return showMetricJobs; }
    public boolean isShowMetricConfig() { return showMetricConfig; }

    public boolean isEnableCsvExport() { return enableCsvExport; }
    public boolean isEnableJsonExport() { return enableJsonExport; }
    public boolean isEnablePdfExport() { return enablePdfExport; }

    public boolean isEnableAuditApi() { return enableAuditApi; }

    /** Return anomaly detection rules as a JSON string for dashboard JS consumption. */
    public String getAnomalyConfigJson() {
        Map<String, Object> anomalyConfig = new LinkedHashMap<>();
        anomalyConfig.put("failedLoginsThreshold", anomalyFailedLoginsThreshold);
        anomalyConfig.put("credentialChangesThreshold", anomalyCredentialChangesThreshold);
        anomalyConfig.put("pluginChangesThreshold", anomalyPluginChangesThreshold);
        anomalyConfig.put("globalConfigChangesThreshold", anomalyGlobalConfigChangesThreshold);
        anomalyConfig.put("jobConfigChangesThreshold", anomalyJobConfigChangesThreshold);
        anomalyConfig.put("securityConfigChangesThreshold", anomalySecurityConfigChangesThreshold);
        anomalyConfig.put("buildFailuresThreshold", anomalyBuildFailuresThreshold);
        return new com.google.gson.Gson().toJson(anomalyConfig);
    }

    private static String toDisplayTimeZoneLabel(String timeZoneId) {
        return sanitizeTimeZoneId(timeZoneId);
    }

    private static List<Map<String, String>> toDisplayTimeZoneOptions(List<String> zoneIds) {
        List<Map<String, String>> options = new ArrayList<>();
        for (String zoneId : zoneIds) {
            Map<String, String> option = new LinkedHashMap<>();
            String sanitized = sanitizeTimeZoneId(zoneId);
            option.put("id", sanitized);
            option.put("label", sanitized);
            option.put("offset", toDisplayTimeZoneOffset(sanitized));
            options.add(option);
        }
        return options;
    }

    private static String toDisplayTimeZoneOffset(String timeZoneId) {
        ZoneOffset offset = ZoneId.of(sanitizeTimeZoneId(timeZoneId))
                .getRules()
                .getOffset(Instant.now());
        return formatUtcOffset(offset);
    }

    private static String formatUtcOffset(ZoneOffset offset) {
        int totalSeconds = offset.getTotalSeconds();
        int totalMinutes = Math.abs(totalSeconds / 60);
        int hours = totalMinutes / 60;
        int minutes = totalMinutes % 60;
        char sign = totalSeconds >= 0 ? '+' : '-';
        return String.format("UTC%c%02d:%02d", sign, hours, minutes);
    }

    private static String escapeJsonString(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}
