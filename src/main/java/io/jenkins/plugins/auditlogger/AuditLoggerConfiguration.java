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
    private boolean enableAuthenticationEvents = true;
    private boolean enableBuildEvents = true;
    private boolean enableJobConfigEvents = true;
    private boolean enablePipelineEvents = true;
    private boolean enableCredentialEvents = true;
    private boolean enablePluginEvents = true;
    private boolean enableSystemConfigEvents = true;
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
    private boolean enableEmailAlerts = false;
    private String alertEmailAddresses = "";
    private boolean enableComplianceReports = false;
    private boolean enableWebhookAlerts = false;
    private String webhookUrl = "";
    private String webhookDestinationsSpec = "";
    
    private boolean enableSlackAlerts = false;
    private String slackWebhookUrl = "";

    private boolean enableTeamsAlerts = false;
    private String teamsWebhookUrl = "";

    // UI
    private boolean enableRiskLevels = true;
    private boolean enableEventCategories = false;
    private boolean enableTimelineView = false;
    private boolean enableSensitiveEventsPanel = false;
    private boolean enableDashboardMetrics = false;
    private boolean enableDashboardStats = true;
    private boolean enableAnomalyRow = false;
    private String displayTimeZoneId = canonicalizeTimeZoneId(ZoneId.systemDefault().getId());
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
        setAnomalyFailedLogins(json.optBoolean("anomalyFailedLogins", false));
        if (json.has("anomalyFailedLoginsThreshold")) {
            setAnomalyFailedLoginsThreshold(json.optInt("anomalyFailedLoginsThreshold", anomalyFailedLoginsThreshold));
        }
        if (json.has("anomalyFailedLoginsWindowMinutes")) {
            setAnomalyFailedLoginsWindowMinutes(json.optInt("anomalyFailedLoginsWindowMinutes", anomalyFailedLoginsWindowMinutes));
        }

        // ── Dashboard display toggles ──
        setEnableDashboardStats(json.optBoolean("enableDashboardStats", false));
        setEnableRiskLevels(json.optBoolean("enableRiskLevels", false));
        if (json.has("displayTimeZoneId")) setDisplayTimeZoneId(json.optString("displayTimeZoneId", displayTimeZoneId));
        setShowMetricTotal(json.optBoolean("showMetricTotal", false));
        setShowMetricLogins(json.optBoolean("showMetricLogins", false));
        setShowMetricFailedLogins(json.optBoolean("showMetricFailedLogins", false));
        setShowMetricBuilds(json.optBoolean("showMetricBuilds", false));
        setShowMetricJobs(json.optBoolean("showMetricJobs", false));
        setShowMetricConfig(json.optBoolean("showMetricConfig", false));

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
        setEnableWebhookAlerts(json.optBoolean("enableWebhookAlerts", false));
        if (json.has("webhookDestinationsSpec")) {
            setWebhookDestinationsSpec(json.optString("webhookDestinationsSpec", webhookDestinationsSpec));
        }
        if (json.has("webhookUrl")) setWebhookUrl(json.optString("webhookUrl", webhookUrl));
        setEnableSlackAlerts(json.optBoolean("enableSlackAlerts", false));
        if (json.has("slackWebhookUrl")) setSlackWebhookUrl(json.optString("slackWebhookUrl", slackWebhookUrl));
        setEnableTeamsAlerts(json.optBoolean("enableTeamsAlerts", false));
        if (json.has("teamsWebhookUrl")) setTeamsWebhookUrl(json.optString("teamsWebhookUrl", teamsWebhookUrl));
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
    public void setEnableDashboardStats(boolean enableDashboardStats) {
        this.enableDashboardStats = enableDashboardStats;
    }


    @DataBoundSetter
    public void setEnableRiskLevels(boolean enableRiskLevels) {
        this.enableRiskLevels = enableRiskLevels;
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
    public void setWebhookDestinationsSpec(String webhookDestinationsSpec) {
        this.webhookDestinationsSpec = normalizeWebhookDestinationsSpec(webhookDestinationsSpec);
    }


    @DataBoundSetter
    public void setEnableSlackAlerts(boolean enableSlackAlerts) {
        this.enableSlackAlerts = enableSlackAlerts;
    }


    @DataBoundSetter
    public void setSlackWebhookUrl(String slackWebhookUrl) {
        this.slackWebhookUrl = slackWebhookUrl;
    }


    @DataBoundSetter
    public void setEnableTeamsAlerts(boolean enableTeamsAlerts) {
        this.enableTeamsAlerts = enableTeamsAlerts;
    }


    @DataBoundSetter
    public void setTeamsWebhookUrl(String teamsWebhookUrl) {
        this.teamsWebhookUrl = teamsWebhookUrl;
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
    public boolean isEnableEmailAlerts() { return enableEmailAlerts; }
    public String getAlertEmailAddresses() { return alertEmailAddresses != null ? alertEmailAddresses : ""; }
    public boolean isEnableComplianceReports() { return enableComplianceReports; }
    public boolean isEnableWebhookAlerts() {
        if (!parseWebhookDestinationsSpec(webhookDestinationsSpec).isEmpty()) {
            return enableWebhookAlerts;
        }
        return enableWebhookAlerts || hasLegacyEnabledWebhookDestinations();
    }
    public String getWebhookUrl() { return webhookUrl != null ? webhookUrl : ""; }
    public boolean isEnableSlackAlerts() { return enableSlackAlerts; }
    public String getSlackWebhookUrl() { return slackWebhookUrl != null ? slackWebhookUrl : ""; }
    public boolean isEnableTeamsAlerts() { return enableTeamsAlerts; }
    public String getTeamsWebhookUrl() { return teamsWebhookUrl != null ? teamsWebhookUrl : ""; }
    public String getWebhookDestinationsSpec() {
        String normalized = normalizeWebhookDestinationsSpec(webhookDestinationsSpec);
        if (!normalized.isEmpty()) {
            return normalized;
        }
        return normalizeWebhookDestinationsSpec(buildLegacyWebhookDestinationsSpec());
    }
    public List<WebhookDestination> getWebhookDestinations() {
        List<WebhookDestination> configured = parseWebhookDestinationsSpec(webhookDestinationsSpec);
        if (!configured.isEmpty()) {
            return configured;
        }
        return buildLegacyWebhookDestinations(false);
    }
    public List<WebhookDestination> getEnabledWebhookDestinations() {
        List<WebhookDestination> configured = parseWebhookDestinationsSpec(webhookDestinationsSpec);
        if (!configured.isEmpty()) {
            return enableWebhookAlerts ? configured : List.of();
        }
        return buildLegacyWebhookDestinations(true);
    }

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

    private boolean hasLegacyEnabledWebhookDestinations() {
        return (enableWebhookAlerts && webhookUrl != null && !webhookUrl.isBlank())
                || (enableSlackAlerts && slackWebhookUrl != null && !slackWebhookUrl.isBlank())
                || (enableTeamsAlerts && teamsWebhookUrl != null && !teamsWebhookUrl.isBlank());
    }

    private String buildLegacyWebhookDestinationsSpec() {
        StringBuilder spec = new StringBuilder();
        appendLegacyWebhookDestination(spec, "generic", webhookUrl);
        appendLegacyWebhookDestination(spec, "slack", slackWebhookUrl);
        appendLegacyWebhookDestination(spec, "teams", teamsWebhookUrl);
        return spec.toString();
    }

    private static void appendLegacyWebhookDestination(StringBuilder spec, String type, String url) {
        if (url == null || url.isBlank()) {
            return;
        }
        if (spec.length() > 0) {
            spec.append('\n');
        }
        spec.append(type).append('|').append(url.trim());
    }

    private List<WebhookDestination> buildLegacyWebhookDestinations(boolean onlyEnabled) {
        List<WebhookDestination> destinations = new ArrayList<>();
        if ((!onlyEnabled || enableWebhookAlerts) && webhookUrl != null && !webhookUrl.isBlank()) {
            destinations.add(new WebhookDestination("generic", webhookUrl.trim()));
        }
        if ((!onlyEnabled || enableSlackAlerts) && slackWebhookUrl != null && !slackWebhookUrl.isBlank()) {
            destinations.add(new WebhookDestination("slack", slackWebhookUrl.trim()));
        }
        if ((!onlyEnabled || enableTeamsAlerts) && teamsWebhookUrl != null && !teamsWebhookUrl.isBlank()) {
            destinations.add(new WebhookDestination("teams", teamsWebhookUrl.trim()));
        }
        return destinations;
    }

    static List<WebhookDestination> parseWebhookDestinationsSpec(String spec) {
        List<WebhookDestination> destinations = new ArrayList<>();
        if (spec == null || spec.isBlank()) {
            return destinations;
        }

        for (String rawLine : spec.split("\\r?\\n")) {
            String line = rawLine == null ? "" : rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            String type = "generic";
            String url = line;
            int pipeIndex = line.indexOf('|');
            if (pipeIndex > 0) {
                String candidateType = normalizeWebhookDestinationType(line.substring(0, pipeIndex));
                String candidateUrl = line.substring(pipeIndex + 1).trim();
                if (candidateType != null && !candidateUrl.isEmpty()) {
                    type = candidateType;
                    url = candidateUrl;
                }
            } else {
                int spaceIndex = line.indexOf(' ');
                if (spaceIndex > 0) {
                    String candidateType = normalizeWebhookDestinationType(line.substring(0, spaceIndex));
                    String candidateUrl = line.substring(spaceIndex + 1).trim();
                    if (candidateType != null && !candidateUrl.isEmpty()) {
                        type = candidateType;
                        url = candidateUrl;
                    }
                }
            }

            if (!url.isEmpty()) {
                destinations.add(new WebhookDestination(type, url));
            }
        }

        return destinations;
    }

    private static String normalizeWebhookDestinationsSpec(String spec) {
        if (spec == null || spec.isBlank()) {
            return "";
        }

        StringBuilder normalized = new StringBuilder();
        for (WebhookDestination destination : parseWebhookDestinationsSpec(spec)) {
            if (normalized.length() > 0) {
                normalized.append('\n');
            }
            normalized.append(destination.getType()).append('|').append(destination.getUrl());
        }
        return normalized.toString();
    }

    private static String normalizeWebhookDestinationType(String rawType) {
        if (rawType == null) {
            return null;
        }

        String normalized = rawType.trim().toLowerCase(java.util.Locale.ENGLISH);
        switch (normalized) {
            case "generic":
            case "webhook":
            case "raw":
                return "generic";
            case "slack":
                return "slack";
            case "teams":
            case "msteams":
            case "microsoft-teams":
            case "microsoftteams":
                return "teams";
            default:
                return null;
        }
    }

    private static String escapeJsonString(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    public static final class WebhookDestination {
        private final String type;
        private final String url;

        WebhookDestination(String type, String url) {
            this.type = type;
            this.url = url;
        }

        public String getType() {
            return type;
        }

        public String getUrl() {
            return url;
        }
    }
}
