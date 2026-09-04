package io.jenkins.plugins.auditlogger;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Logger;

import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.verb.GET;

import hudson.BulkChange;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.ListBoxModel;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

/**
 * Global configuration for Jenkins Audit Logger plugin.
 * Manage Jenkins -> Configure System -> Audit Logger
 */
@Extension
public class AuditLoggerConfiguration extends GlobalConfiguration {
    private static final Logger LOGGER = Logger.getLogger(AuditLoggerConfiguration.class.getName());
    private static final String DEFAULT_DISPLAY_TIME_ZONE = "UTC";
        private static final Set<String> UTC_EQUIVALENT_TIME_ZONES = Set.of(
            "Etc/GMT",
            "Etc/UCT",
            "Etc/UTC",
            "GMT",
            "UCT",
            "UTC",
            "Universal",
            "Zulu");
        private static final Map<String, String> DISPLAY_TIME_ZONE_ALIASES = Map.of(
            "Asia/Kolkata", "India Standard Time",
            "UTC", "Coordinated Universal Time");
        private static final Map<String, String> DISPLAY_TIME_ZONE_SEARCH_ALIASES = Map.of(
            "Asia/Kolkata", "Chennai Kolkata Mumbai New Delhi India Standard Time IST",
            "UTC", "Coordinated Universal Time GMT Zulu");
    private static final List<String> AVAILABLE_DISPLAY_TIME_ZONES = buildAvailableDisplayTimeZoneIds();

    // Event Categories
    private Boolean enableAuthenticationEvents = true;
    private Boolean enableBuildEvents = true;
    private Boolean enableJobConfigEvents = true;
    private boolean enablePipelineEvents = true;
    private Boolean enableCredentialEvents = true;
    private Boolean enablePluginEvents = true;
    private Boolean enableSystemConfigEvents = true;
    private Boolean enableNodeEvents = true;
    private boolean enableApiEvents = false;

    // Risk Detection — temporarily disabled to keep the write path lightweight.
    private Boolean anomalyFailedLogins = false;
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

    // Phase 2 — Expanded Security Anomaly Detection
    private boolean anomalyUnusualIp = false;
    private int anomalyUnusualIpWindowMinutes = 60;

    private boolean anomalyMultiIpLogin = false;
    private int anomalyMultiIpLoginThreshold = 2;
    private int anomalyMultiIpLoginWindowMinutes = 15;

    private boolean anomalySuspiciousAuth = false;

    private boolean anomalyAdminPrivilegeChanges = false;

    private boolean anomalyUserLifecycle = false;
    private int anomalyUserLifecycleThreshold = 1;
    private int anomalyUserLifecycleWindowMinutes = 15;

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
    private Boolean enableLogRotation = true;

    // Startup
    private int startupGracePeriodSeconds = 120;

    // Optimization
    private boolean enableAdvancedIndexing = false;
    private Boolean enableAnomalyDetection = true;
    private boolean enableMetricsCollection = false;
    private int batchWriteSize = 100;
    private int batchFlushIntervalSeconds = 5;

    // Privacy
    private Boolean maskTokens = true;
    private Boolean maskEmailAddresses = false;
    private Boolean maskCreditCards = true;

    // Alerts
    private boolean enableAlertEngine = false;
    private Boolean enableEmailAlerts = false;
    private String alertEmailAddresses = "";
    private boolean enableComplianceReports = false;
    private Boolean enableWebhookAlerts = false;
    private String webhookUrl = "";

    // UI
    private boolean enableRiskLevels = true;
    private boolean enableAnomalyBanner = true;
    private boolean enableEventCategories = false;
    private boolean enableTimelineView = false;
    private boolean enableSensitiveEventsPanel = false;
    private boolean enableDashboardMetrics = false;
    private Boolean enableDashboardStats = true;
    private boolean enableAnomalyRow = false;
    private String displayTimeZoneId = canonicalizeTimeZoneId(ZoneId.systemDefault().getId());
    private Boolean showMetricTotal = true;
    private Boolean showMetricLogins = true;
    private Boolean showMetricFailedLogins = true;
    private Boolean showMetricBuilds = true;
    private Boolean showMetricJobs = true;
    private Boolean showMetricConfig = true;

    // Export
    private Boolean enableCsvExport = true;
    private Boolean enableJsonExport = true;
    private boolean enablePdfExport = false;

    // REST API
    private Boolean enableAuditApi = true;

    
    protected Object readResolve() {
        if (enableAuthenticationEvents == null) enableAuthenticationEvents = true;
        if (enableBuildEvents == null) enableBuildEvents = true;
        if (enableJobConfigEvents == null) enableJobConfigEvents = true;
        if (enableCredentialEvents == null) enableCredentialEvents = true;
        if (enablePluginEvents == null) enablePluginEvents = true;
        if (enableSystemConfigEvents == null) enableSystemConfigEvents = true;
        if (enableNodeEvents == null) enableNodeEvents = true;
        if (anomalyFailedLogins == null) anomalyFailedLogins = true;
        if (enableAnomalyDetection == null) enableAnomalyDetection = true;
        if (enableLogRotation == null) enableLogRotation = true;
        if (maskTokens == null) maskTokens = true;
        if (maskEmailAddresses == null) maskEmailAddresses = false;
        if (maskCreditCards == null) maskCreditCards = true;
        if (enableEmailAlerts == null) enableEmailAlerts = false;
        if (enableWebhookAlerts == null) enableWebhookAlerts = false;
        if (enableDashboardStats == null) enableDashboardStats = true;
        if (showMetricTotal == null) showMetricTotal = true;
        if (showMetricLogins == null) showMetricLogins = true;
        if (showMetricFailedLogins == null) showMetricFailedLogins = true;
        if (showMetricBuilds == null) showMetricBuilds = true;
        if (showMetricJobs == null) showMetricJobs = true;
        if (showMetricConfig == null) showMetricConfig = true;
        if (enableCsvExport == null) enableCsvExport = true;
        if (enableJsonExport == null) enableJsonExport = true;
        if (enableAuditApi == null) enableAuditApi = true;
        return this;
    }

    public AuditLoggerConfiguration() {
        load();
        readResolve();
        displayTimeZoneId = sanitizeTimeZoneId(displayTimeZoneId);
    }

    public static AuditLoggerConfiguration get() {
        return GlobalConfiguration.all().get(AuditLoggerConfiguration.class);
    }

    @Override
    public boolean configure(StaplerRequest2 req, JSONObject json) throws Descriptor.FormException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        try (BulkChange bulkChange = new BulkChange(this)) {
            applyJsonConfiguration(json);
            StartupPhaseManager.setGracePeriodSeconds(startupGracePeriodSeconds);
            bulkChange.commit();
            return true;
        } catch (IOException e) {
            LOGGER.warning("Failed to save AuditFlow configuration: " + e.getMessage());
            return false;
        }
    }

    private void applyJsonConfiguration(JSONObject json) {
        if (json == null) {
            return;
        }

        // ── Event category toggles ──
        // NOTE: Do NOT use json.has() for checkboxes — Jenkins f:checkbox omits
        // the key entirely when unchecked, so json.has() returns false and the
        // setter is never called.  optBoolean() already returns false for
        // missing keys, which is the correct "unchecked" value.
        setEnableAuthenticationEvents(json.optBoolean("enableAuthenticationEvents", false));
        setEnableBuildEvents(json.optBoolean("enableBuildEvents", false));
        setEnableJobConfigEvents(json.optBoolean("enableJobConfigEvents", false));
        setEnableCredentialEvents(json.optBoolean("enableCredentialEvents", false));
        setEnablePluginEvents(json.optBoolean("enablePluginEvents", false));
        setEnableSystemConfigEvents(json.optBoolean("enableSystemConfigEvents", false));
        setEnableNodeEvents(json.optBoolean("enableNodeEvents", false));
        // ── Security Anomaly Detection Master Block ──
        JSONObject anomalyDetectionBlock = getOptionalBlock(json, "enableAnomalyDetection");
        setEnableAnomalyDetection(isOptionalBlockEnabled(json, "enableAnomalyDetection"));
        JSONObject anomalyConfig = anomalyDetectionBlock != null ? anomalyDetectionBlock : json;

        JSONObject failedLoginBlock = getOptionalBlock(anomalyConfig, "anomalyFailedLogins");
        setAnomalyFailedLogins(isOptionalBlockEnabled(anomalyConfig, "anomalyFailedLogins"));
        JSONObject failedLoginConfig = failedLoginBlock != null ? failedLoginBlock : anomalyConfig;
        if (failedLoginConfig.has("anomalyFailedLoginsThreshold")) {
            setAnomalyFailedLoginsThreshold(failedLoginConfig.optInt("anomalyFailedLoginsThreshold", anomalyFailedLoginsThreshold));
        }
        if (failedLoginConfig.has("anomalyFailedLoginsWindowMinutes")) {
            setAnomalyFailedLoginsWindowMinutes(failedLoginConfig.optInt("anomalyFailedLoginsWindowMinutes", anomalyFailedLoginsWindowMinutes));
        }

        // Phase 2 Anomaly Detection Blocks
        JSONObject unusualIpBlock = getOptionalBlock(anomalyConfig, "anomalyUnusualIp");
        setAnomalyUnusualIp(isOptionalBlockEnabled(anomalyConfig, "anomalyUnusualIp"));
        JSONObject unusualIpConfig = unusualIpBlock != null ? unusualIpBlock : anomalyConfig;
        if (unusualIpConfig.has("anomalyUnusualIpWindowMinutes")) {
            setAnomalyUnusualIpWindowMinutes(unusualIpConfig.optInt("anomalyUnusualIpWindowMinutes", anomalyUnusualIpWindowMinutes));
        }

        JSONObject multiIpBlock = getOptionalBlock(anomalyConfig, "anomalyMultiIpLogin");
        setAnomalyMultiIpLogin(isOptionalBlockEnabled(anomalyConfig, "anomalyMultiIpLogin"));
        JSONObject multiIpConfig = multiIpBlock != null ? multiIpBlock : anomalyConfig;
        if (multiIpConfig.has("anomalyMultiIpLoginThreshold")) {
            setAnomalyMultiIpLoginThreshold(multiIpConfig.optInt("anomalyMultiIpLoginThreshold", anomalyMultiIpLoginThreshold));
        }
        if (multiIpConfig.has("anomalyMultiIpLoginWindowMinutes")) {
            setAnomalyMultiIpLoginWindowMinutes(multiIpConfig.optInt("anomalyMultiIpLoginWindowMinutes", anomalyMultiIpLoginWindowMinutes));
        }

        setAnomalySuspiciousAuth(anomalyConfig.optBoolean("anomalySuspiciousAuth", false));
        setAnomalyAdminPrivilegeChanges(anomalyConfig.optBoolean("anomalyAdminPrivilegeChanges", false));

        JSONObject userLifecycleBlock = getOptionalBlock(anomalyConfig, "anomalyUserLifecycle");
        setAnomalyUserLifecycle(isOptionalBlockEnabled(anomalyConfig, "anomalyUserLifecycle"));
        JSONObject userLifecycleConfig = userLifecycleBlock != null ? userLifecycleBlock : anomalyConfig;
        if (userLifecycleConfig.has("anomalyUserLifecycleThreshold")) {
            setAnomalyUserLifecycleThreshold(userLifecycleConfig.optInt("anomalyUserLifecycleThreshold", anomalyUserLifecycleThreshold));
        }
        if (userLifecycleConfig.has("anomalyUserLifecycleWindowMinutes")) {
            setAnomalyUserLifecycleWindowMinutes(userLifecycleConfig.optInt("anomalyUserLifecycleWindowMinutes", anomalyUserLifecycleWindowMinutes));
        }
        setEnableAnomalyBanner(anomalyConfig.optBoolean("enableAnomalyBanner", json.optBoolean("enableAnomalyBanner", false)));

        JSONObject dashboardStatsBlock = getOptionalBlock(json, "enableDashboardStats");
        setEnableDashboardStats(isOptionalBlockEnabled(json, "enableDashboardStats"));
        setEnableRiskLevels(json.optBoolean("enableRiskLevels", false));
        if (json.has("displayTimeZoneId")) setDisplayTimeZoneId(json.optString("displayTimeZoneId", displayTimeZoneId));
        JSONObject dashboardStatsConfig = dashboardStatsBlock != null ? dashboardStatsBlock : json;
        setShowMetricTotal(dashboardStatsConfig.optBoolean("showMetricTotal", false));
        setShowMetricLogins(dashboardStatsConfig.optBoolean("showMetricLogins", false));
        setShowMetricFailedLogins(dashboardStatsConfig.optBoolean("showMetricFailedLogins", false));
        setShowMetricBuilds(dashboardStatsConfig.optBoolean("showMetricBuilds", false));
        setShowMetricJobs(dashboardStatsConfig.optBoolean("showMetricJobs", false));
        setShowMetricConfig(dashboardStatsConfig.optBoolean("showMetricConfig", false));

        // ── Export toggles ──
        setEnableCsvExport(json.optBoolean("enableCsvExport", false));
        setEnableJsonExport(json.optBoolean("enableJsonExport", false));
        setEnableAuditApi(json.optBoolean("enableAuditApi", false));

        // ── Advanced (non-boolean fields keep json.has() guard) ──
        if (json.has("logRetentionDays")) setLogRetentionDays(json.optInt("logRetentionDays", logRetentionDays));
        if (json.has("maxLogFileSizeMB")) setMaxLogFileSizeMB(json.optInt("maxLogFileSizeMB", maxLogFileSizeMB));
        setEnableLogRotation(json.optBoolean("enableLogRotation", false));
        if (json.has("startupGracePeriodSeconds")) setStartupGracePeriodSeconds(json.optInt("startupGracePeriodSeconds", startupGracePeriodSeconds));
        if (json.has("batchWriteSize")) setBatchWriteSize(json.optInt("batchWriteSize", batchWriteSize));
        if (json.has("batchFlushIntervalSeconds")) setBatchFlushIntervalSeconds(json.optInt("batchFlushIntervalSeconds", batchFlushIntervalSeconds));

        // ── Privacy toggles ──
        setMaskTokens(json.optBoolean("maskTokens", false));
        setMaskEmailAddresses(json.optBoolean("maskEmailAddresses", false));
        setMaskCreditCards(json.optBoolean("maskCreditCards", false));

        // ── Notification toggles (same fix: no json.has() for checkboxes) ──
        JSONObject emailAlertsBlock = getOptionalBlock(json, "enableEmailAlerts");
        setEnableEmailAlerts(isOptionalBlockEnabled(json, "enableEmailAlerts"));
        JSONObject emailAlertsConfig = emailAlertsBlock != null ? emailAlertsBlock : json;
        if (emailAlertsConfig.has("alertEmailAddresses")) setAlertEmailAddresses(emailAlertsConfig.optString("alertEmailAddresses", alertEmailAddresses));
        JSONObject webhookAlertsBlock = getOptionalBlock(json, "enableWebhookAlerts");
        setEnableWebhookAlerts(isOptionalBlockEnabled(json, "enableWebhookAlerts"));
        JSONObject webhookAlertsConfig = webhookAlertsBlock != null ? webhookAlertsBlock : json;
        if (webhookAlertsConfig.has("webhookUrl")) setWebhookUrl(webhookAlertsConfig.optString("webhookUrl", webhookUrl));
    }

    private static JSONObject getOptionalBlock(JSONObject json, String key) {
        Object value = json.opt(key);
        return value instanceof JSONObject ? (JSONObject) value : null;
    }

    private static boolean isOptionalBlockEnabled(JSONObject json, String key) {
        return getOptionalBlock(json, key) != null || json.optBoolean(key, false);
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private static List<String> buildAvailableDisplayTimeZoneIds() {
        String systemTimeZoneId = canonicalizeTimeZoneId(ZoneId.systemDefault().getId());
        Set<String> availableTimeZones = new TreeSet<>();
        for (String zoneId : ZoneId.getAvailableZoneIds()) {
            availableTimeZones.add(canonicalizeTimeZoneId(zoneId));
        }
        availableTimeZones.remove(systemTimeZoneId);
        availableTimeZones.remove(DEFAULT_DISPLAY_TIME_ZONE);

        Set<String> orderedTimeZones = new LinkedHashSet<>();
        orderedTimeZones.add(systemTimeZoneId);
        if (!DEFAULT_DISPLAY_TIME_ZONE.equals(systemTimeZoneId)) {
            orderedTimeZones.add(DEFAULT_DISPLAY_TIME_ZONE);
        }
        orderedTimeZones.addAll(availableTimeZones);
        return List.copyOf(orderedTimeZones);
    }

    static String canonicalizeTimeZoneId(String value) {
        if (value == null || value.trim().isEmpty()) {
            return DEFAULT_DISPLAY_TIME_ZONE;
        }

        String candidate = value.trim();
        if (UTC_EQUIVALENT_TIME_ZONES.contains(candidate)) {
            return DEFAULT_DISPLAY_TIME_ZONE;
        }

        return ZoneId.of(candidate).getId();
    }

    private static String sanitizeTimeZoneId(String value) {
        if (value == null || value.trim().isEmpty()) {
            return DEFAULT_DISPLAY_TIME_ZONE;
        }

        try {
            String normalized = canonicalizeTimeZoneId(value);
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
    }


    @DataBoundSetter
    public void setEnableBuildEvents(boolean enableBuildEvents) {
        this.enableBuildEvents = enableBuildEvents;
    }


    @DataBoundSetter
    public void setEnableJobConfigEvents(boolean enableJobConfigEvents) {
        this.enableJobConfigEvents = enableJobConfigEvents;
    }


    @DataBoundSetter
    public void setEnableCredentialEvents(boolean enableCredentialEvents) {
        this.enableCredentialEvents = enableCredentialEvents;
    }


    @DataBoundSetter
    public void setEnablePluginEvents(boolean enablePluginEvents) {
        this.enablePluginEvents = enablePluginEvents;
    }


    @DataBoundSetter
    public void setEnableSystemConfigEvents(boolean enableSystemConfigEvents) {
        this.enableSystemConfigEvents = enableSystemConfigEvents;
    }

    @DataBoundSetter
    public void setEnableNodeEvents(boolean enableNodeEvents) {
        this.enableNodeEvents = enableNodeEvents;
    }


    @DataBoundSetter
    public void setAnomalyFailedLogins(boolean anomalyFailedLogins) {
        this.anomalyFailedLogins = anomalyFailedLogins;
    }


    @DataBoundSetter
    public void setAnomalyFailedLoginsThreshold(int anomalyFailedLoginsThreshold) {
        this.anomalyFailedLoginsThreshold = clamp(anomalyFailedLoginsThreshold, 2, 1000);
    }


    @DataBoundSetter
    public void setAnomalyFailedLoginsWindowMinutes(int anomalyFailedLoginsWindowMinutes) {
        this.anomalyFailedLoginsWindowMinutes = clamp(anomalyFailedLoginsWindowMinutes, 1, 1440);
    }

    @DataBoundSetter
    public void setAnomalyUnusualIp(boolean anomalyUnusualIp) {
        this.anomalyUnusualIp = anomalyUnusualIp;
    }

    @DataBoundSetter
    public void setAnomalyUnusualIpWindowMinutes(int anomalyUnusualIpWindowMinutes) {
        this.anomalyUnusualIpWindowMinutes = clamp(anomalyUnusualIpWindowMinutes, 1, 1440);
    }

    @DataBoundSetter
    public void setAnomalyMultiIpLogin(boolean anomalyMultiIpLogin) {
        this.anomalyMultiIpLogin = anomalyMultiIpLogin;
    }

    @DataBoundSetter
    public void setAnomalyMultiIpLoginThreshold(int anomalyMultiIpLoginThreshold) {
        this.anomalyMultiIpLoginThreshold = clamp(anomalyMultiIpLoginThreshold, 2, 100);
    }

    @DataBoundSetter
    public void setAnomalyMultiIpLoginWindowMinutes(int anomalyMultiIpLoginWindowMinutes) {
        this.anomalyMultiIpLoginWindowMinutes = clamp(anomalyMultiIpLoginWindowMinutes, 1, 1440);
    }

    @DataBoundSetter
    public void setAnomalySuspiciousAuth(boolean anomalySuspiciousAuth) {
        this.anomalySuspiciousAuth = anomalySuspiciousAuth;
    }

    @DataBoundSetter
    public void setAnomalyAdminPrivilegeChanges(boolean anomalyAdminPrivilegeChanges) {
        this.anomalyAdminPrivilegeChanges = anomalyAdminPrivilegeChanges;
    }

    @DataBoundSetter
    public void setAnomalyUserLifecycle(boolean anomalyUserLifecycle) {
        this.anomalyUserLifecycle = anomalyUserLifecycle;
    }

    @DataBoundSetter
    public void setAnomalyUserLifecycleThreshold(int anomalyUserLifecycleThreshold) {
        this.anomalyUserLifecycleThreshold = clamp(anomalyUserLifecycleThreshold, 1, 100);
    }

    @DataBoundSetter
    public void setAnomalyUserLifecycleWindowMinutes(int anomalyUserLifecycleWindowMinutes) {
        this.anomalyUserLifecycleWindowMinutes = clamp(anomalyUserLifecycleWindowMinutes, 1, 1440);
    }


    @DataBoundSetter
    public void setEnableDashboardStats(boolean enableDashboardStats) {
        this.enableDashboardStats = enableDashboardStats;
    }

    @DataBoundSetter
    public void setEnableAnomalyDetection(boolean enableAnomalyDetection) {
        this.enableAnomalyDetection = enableAnomalyDetection;
    }


    @DataBoundSetter
    public void setEnableRiskLevels(boolean enableRiskLevels) {
        this.enableRiskLevels = enableRiskLevels;
    }

    public boolean isEnableAnomalyBanner() {
        return enableAnomalyBanner;
    }

    @DataBoundSetter
    public void setEnableAnomalyBanner(boolean enableAnomalyBanner) {
        this.enableAnomalyBanner = enableAnomalyBanner;
    }


    @DataBoundSetter
    public void setDisplayTimeZoneId(String displayTimeZoneId) {
        this.displayTimeZoneId = sanitizeTimeZoneId(displayTimeZoneId);
    }


    @DataBoundSetter
    public void setShowMetricTotal(boolean showMetricTotal) {
        this.showMetricTotal = showMetricTotal;
    }


    @DataBoundSetter
    public void setShowMetricLogins(boolean showMetricLogins) {
        this.showMetricLogins = showMetricLogins;
    }


    @DataBoundSetter
    public void setShowMetricFailedLogins(boolean showMetricFailedLogins) {
        this.showMetricFailedLogins = showMetricFailedLogins;
    }


    @DataBoundSetter
    public void setShowMetricBuilds(boolean showMetricBuilds) {
        this.showMetricBuilds = showMetricBuilds;
    }


    @DataBoundSetter
    public void setShowMetricJobs(boolean showMetricJobs) {
        this.showMetricJobs = showMetricJobs;
    }


    @DataBoundSetter
    public void setShowMetricConfig(boolean showMetricConfig) {
        this.showMetricConfig = showMetricConfig;
    }


    @DataBoundSetter
    public void setEnableCsvExport(boolean enableCsvExport) {
        this.enableCsvExport = enableCsvExport;
    }


    @DataBoundSetter
    public void setEnableJsonExport(boolean enableJsonExport) {
        this.enableJsonExport = enableJsonExport;
    }


    @DataBoundSetter
    public void setEnableAuditApi(boolean enableAuditApi) {
        this.enableAuditApi = enableAuditApi;
    }


    @DataBoundSetter
    public void setEnableAlertEngine(boolean enableAlertEngine) {
        this.enableAlertEngine = enableAlertEngine;
    }


    @DataBoundSetter
    public void setEnableEmailAlerts(boolean enableEmailAlerts) {
        this.enableEmailAlerts = enableEmailAlerts;
    }

    //add
    @DataBoundSetter
    public void setEnableWebhookAlerts(boolean enableWebhookAlerts) {
        this.enableWebhookAlerts = enableWebhookAlerts;
    }


    @DataBoundSetter
    public void setAlertEmailAddresses(String alertEmailAddresses) {
        this.alertEmailAddresses = alertEmailAddresses;
    }

    //add
    @DataBoundSetter
    public void setWebhookUrl(String webhookUrl) {
        this.webhookUrl = webhookUrl;
    }


    @DataBoundSetter
    public void setLogRetentionDays(int logRetentionDays) {
        this.logRetentionDays = clamp(logRetentionDays, 0, 3650);
    }


    @DataBoundSetter
    public void setMaxLogFileSizeMB(int maxLogFileSizeMB) {
        this.maxLogFileSizeMB = clamp(maxLogFileSizeMB, 1, 1024);
    }


    @DataBoundSetter
    public void setEnableLogRotation(boolean enableLogRotation) {
        this.enableLogRotation = enableLogRotation;
    }


    @DataBoundSetter
    public void setStartupGracePeriodSeconds(int startupGracePeriodSeconds) {
        this.startupGracePeriodSeconds = clamp(startupGracePeriodSeconds, 5, 300);
        StartupPhaseManager.setGracePeriodSeconds(this.startupGracePeriodSeconds);
    }


    @DataBoundSetter
    public void setBatchWriteSize(int batchWriteSize) {
        this.batchWriteSize = clamp(batchWriteSize, 1, 10000);
    }


    @DataBoundSetter
    public void setBatchFlushIntervalSeconds(int batchFlushIntervalSeconds) {
        this.batchFlushIntervalSeconds = clamp(batchFlushIntervalSeconds, 1, 300);
    }


    @DataBoundSetter
    public void setMaskTokens(boolean maskTokens) {
        this.maskTokens = maskTokens;
    }


    @DataBoundSetter
    public void setMaskEmailAddresses(boolean maskEmailAddresses) {
        this.maskEmailAddresses = maskEmailAddresses;
    }


    @DataBoundSetter
    public void setMaskCreditCards(boolean maskCreditCards) {
        this.maskCreditCards = maskCreditCards;
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

    // Phase 2 getters
    public boolean isAnomalyUnusualIp() { return anomalyUnusualIp; }
    public int getAnomalyUnusualIpWindowMinutes() { return anomalyUnusualIpWindowMinutes; }
    public boolean isAnomalyMultiIpLogin() { return anomalyMultiIpLogin; }
    public int getAnomalyMultiIpLoginThreshold() { return anomalyMultiIpLoginThreshold; }
    public int getAnomalyMultiIpLoginWindowMinutes() { return anomalyMultiIpLoginWindowMinutes; }
    public boolean isAnomalySuspiciousAuth() { return anomalySuspiciousAuth; }
    public boolean isAnomalyAdminPrivilegeChanges() { return anomalyAdminPrivilegeChanges; }
    public boolean isAnomalyUserLifecycle() { return anomalyUserLifecycle; }
    public int getAnomalyUserLifecycleThreshold() { return anomalyUserLifecycleThreshold; }
    public int getAnomalyUserLifecycleWindowMinutes() { return anomalyUserLifecycleWindowMinutes; }

    public int getLogRetentionDays() { return logRetentionDays; }
    public int getMaxLogFileSizeMB() { return maxLogFileSizeMB; }
    public long getMaxLogFileSizeBytes() { return (long) maxLogFileSizeMB * 1024L * 1024L; }
    public boolean isEnableLogRotation() { return enableLogRotation; }

    public int getStartupGracePeriodSeconds() { return startupGracePeriodSeconds; }

    public boolean isEnableAdvancedIndexing() { return enableAdvancedIndexing; }
    public boolean isEnableAnomalyDetection() { return enableAnomalyDetection == null || enableAnomalyDetection; }
    public boolean isEnableMetricsCollection() { return enableMetricsCollection; }
    public int getBatchWriteSize() { return batchWriteSize; }
    public int getBatchFlushIntervalSeconds() { return batchFlushIntervalSeconds; }

    public boolean isMaskTokens() { return maskTokens; }
    public boolean isMaskEmailAddresses() { return maskEmailAddresses; }
    public boolean isMaskCreditCards() { return maskCreditCards; }

    public boolean isEnableAlertEngine() { return enableAlertEngine; }
    public boolean isEnableEmailAlerts() { return enableEmailAlerts; }
    public String getAlertEmailAddresses() { return alertEmailAddresses != null ? alertEmailAddresses : ""; }
    public boolean isEnableComplianceReports() { return enableComplianceReports; }
    public boolean isEnableWebhookAlerts() { return enableWebhookAlerts; }
    public String getWebhookUrl() { return webhookUrl != null ? webhookUrl : ""; }

    public boolean isEnableRiskLevels() { return enableRiskLevels; }
    public boolean isEnableEventCategories() { return enableEventCategories; }
    public boolean isEnableTimelineView() { return enableTimelineView; }
    public boolean isEnableSensitiveEventsPanel() { return enableSensitiveEventsPanel; }
    public boolean isEnableDashboardMetrics() { return enableDashboardMetrics; }
    public boolean isEnableDashboardStats() { return enableDashboardStats; }
    public boolean isEnableAnomalyRow() { return false; }
    public String getDisplayTimeZoneId() { return sanitizeTimeZoneId(displayTimeZoneId); }
    public String getDisplayTimeZoneDisplayName() {
        return toDisplayTimeZoneLabel(getDisplayTimeZoneId());
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

    @GET
    public ListBoxModel doFillDisplayTimeZoneIdItems() {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
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

    public boolean isEnableAuditApi() { return true; }

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
        anomalyConfig.put("unusualIpEnabled", anomalyUnusualIp);
        anomalyConfig.put("unusualIpWindowMinutes", anomalyUnusualIpWindowMinutes);
        anomalyConfig.put("multiIpLoginEnabled", anomalyMultiIpLogin);
        anomalyConfig.put("multiIpLoginThreshold", anomalyMultiIpLoginThreshold);
        anomalyConfig.put("multiIpLoginWindowMinutes", anomalyMultiIpLoginWindowMinutes);
        anomalyConfig.put("suspiciousAuthEnabled", anomalySuspiciousAuth);
        anomalyConfig.put("adminPrivilegeChangesEnabled", anomalyAdminPrivilegeChanges);
        anomalyConfig.put("userLifecycleEnabled", anomalyUserLifecycle);
        anomalyConfig.put("userLifecycleThreshold", anomalyUserLifecycleThreshold);
        anomalyConfig.put("userLifecycleWindowMinutes", anomalyUserLifecycleWindowMinutes);
        return new com.google.gson.Gson().toJson(anomalyConfig);
    }

    private static String toDisplayTimeZoneLabel(String timeZoneId) {
        String sanitized = sanitizeTimeZoneId(timeZoneId);
        String alias = DISPLAY_TIME_ZONE_ALIASES.get(sanitized);
        String label = alias != null ? alias + " (" + sanitized + ")" : sanitized;
        if (sanitized.equals(canonicalizeTimeZoneId(ZoneId.systemDefault().getId()))) {
            return "System Default - " + label;
        }
        return label;
    }

    private static String toDisplayTimeZoneSearchText(String timeZoneId) {
        String sanitized = sanitizeTimeZoneId(timeZoneId);
        String alias = DISPLAY_TIME_ZONE_ALIASES.getOrDefault(sanitized, "");
        String extraAliases = DISPLAY_TIME_ZONE_SEARCH_ALIASES.getOrDefault(sanitized, "");
        return String.join(" ",
                sanitized,
                toDisplayTimeZoneLabel(sanitized),
                alias,
                extraAliases,
                toDisplayTimeZoneOffset(sanitized)).trim();
    }

    private static List<Map<String, String>> toDisplayTimeZoneOptions(List<String> zoneIds) {
        List<Map<String, String>> options = new ArrayList<>();
        for (String zoneId : zoneIds) {
            Map<String, String> option = new LinkedHashMap<>();
            String sanitized = sanitizeTimeZoneId(zoneId);
            option.put("id", sanitized);
            option.put("label", toDisplayTimeZoneLabel(sanitized));
            option.put("offset", toDisplayTimeZoneOffset(sanitized));
            option.put("searchText", toDisplayTimeZoneSearchText(sanitized));
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
