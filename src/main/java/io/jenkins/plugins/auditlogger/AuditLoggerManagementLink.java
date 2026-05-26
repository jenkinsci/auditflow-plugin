package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.ManagementLink;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.kohsuke.stapler.verb.GET;

import java.io.IOException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Management link: web UI, paged JSON API, and exports with display-timezone support.
 */
@Extension
public class AuditLoggerManagementLink extends ManagementLink {
    private static final Logger LOGGER = Logger.getLogger(AuditLoggerManagementLink.class.getName());
    private static final String DISPLAY_VERSION = "v1.0.0";
    private static final int DEFAULT_PAGE_SIZE = 100;
    private static final int MAX_PAGE_SIZE = 5_000;
    private static final int MAX_EXPORT_ROWS = 100_000;
    private static final long DAY_MS = 24L * 60L * 60L * 1000L;

    @Override
    public String getIconFileName() {
        return "symbol-document-text-outline plugin-ionicons-api";
    }

    @Override
    public String getDisplayName() {
        return "AuditFlow Logs";
    }

    public String getPageTitle() {
        return "AuditFlow - " + getPluginVersion();
    }

    public String getPageHeading() {
        return getPageTitle();
    }

    public String getPluginVersion() {
        return DISPLAY_VERSION;
    }

    @Override
    public String getUrlName() {
        return "auditflow-logs";
    }

    @Override
    public String getDescription() {
        return "View and export audit trail: authentication, builds, job lifecycle, and configuration changes.";
    }

    @Override
    public Category getCategory() {
        return Category.SECURITY;
    }

    @Override
    public Permission getRequiredPermission() {
        return Jenkins.ADMINISTER;
    }

    @GET
    public void doApi(StaplerRequest2 req, StaplerResponse2 res) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        if (config != null && !config.isEnableAuditApi()) {
            res.setStatus(403);
            res.setContentType("application/json; charset=UTF-8");
            res.getWriter().write("{\"error\":\"Audit API is disabled in configuration\",\"logs\":[]}");
            return;
        }

        try {
            ZoneId displayZone = resolveDisplayZone(config);
            AuditViewRequest viewRequest = AuditViewRequest.fromRequest(req, displayZone);
            List<AuditLogEntry> filteredEntries = loadFilteredEntries(viewRequest, displayZone);
            PageSlice page = paginateEntries(filteredEntries, viewRequest.page, viewRequest.pageSize);

            res.setContentType("application/json; charset=UTF-8");
            var gson = new com.google.gson.GsonBuilder().create();
            var response = new LinkedHashMap<String, Object>();
            response.put("total", filteredEntries.size());
            response.put("page", page.page);
            response.put("pageSize", page.pageSize);
            response.put("totalPages", page.totalPages);
            response.put("logs", toDisplayEntries(page.entries, displayZone));
            response.put("summary", buildSummary(filteredEntries, displayZone));
            response.put("insights", buildInsights(filteredEntries, config, displayZone));
            response.put("anomalyConfig", buildAnomalyConfig(config));
            response.put("displayTimeZone", displayZone.getId());
            response.put("displayToday", LocalDate.now(displayZone).toString());
            res.getWriter().write(gson.toJson(response));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in doApi", e);
            res.setContentType("application/json; charset=UTF-8");
            res.getWriter().write("{\"error\":\"Internal server error\",\"logs\":[]}");
        }
    }

    @GET
    public void doExportCsv(StaplerRequest2 req, StaplerResponse2 res) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        AuditLoggerConfiguration cfg = AuditLoggerConfiguration.get();
        if (cfg != null && !cfg.isEnableCsvExport()) {
            res.setStatus(403);
            res.getWriter().write("CSV export is disabled in configuration");
            return;
        }

        try {
            ZoneId displayZone = resolveDisplayZone(cfg);
            AuditViewRequest viewRequest = AuditViewRequest.fromRequest(req, displayZone);
            List<AuditLogEntry> entries = loadFilteredEntries(viewRequest, displayZone);

            if (entries.size() > MAX_EXPORT_ROWS) {
                entries = entries.subList(0, MAX_EXPORT_ROWS);
            }

            String filename = "auditflow-logs-" + LocalDate.now(displayZone) + ".csv";
            res.setContentType("text/csv; charset=UTF-8");
            res.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

            try (var writer = res.getWriter()) {
                writer.println("Timestamp,User,Action,Target,Details,SourceIP,AuthMethod,TriggerType,Severity,SessionID,UserAgent");
                for (AuditLogEntry entry : entries) {
                    writer.println(String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
                            csvSafe(entry.getReadableTimestamp(displayZone)),
                            csvSafe(entry.getUsername()),
                            csvSafe(entry.getAction()),
                            csvSafe(entry.getTarget()),
                            csvSafe(entry.getDetails()),
                            csvSafe(entry.getSourceIp()),
                            csvSafe(entry.getAuthMethod()),
                            csvSafe(entry.getTriggerType()),
                            csvSafe(entry.getSeverity()),
                            csvSafe(entry.getSessionId()),
                            csvSafe(entry.getUserAgent())));
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in CSV export", e);
            res.getWriter().write("Error generating export");
        }
    }

    /**
     * Escape CSV value: quote the field, escape internal quotes,
     * and prefix formula-injection characters to prevent spreadsheet attacks.
     */
    private static String csvSafe(String value) {
        if (value == null) return "\"\"";
        String safe = value;
        if (!safe.isEmpty()) {
            char first = safe.charAt(0);
            if (first == '=' || first == '+' || first == '-' || first == '@'
                    || first == '|' || first == '\t') {
                safe = "'" + safe;
            }
        }
        safe = safe.replace("\"", "\"\"");
        return "\"" + safe + "\"";
    }

    private static Long parseLong(String value) {
        if (value == null || value.isEmpty()) return null;
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static int parseInt(String value, int defaultValue) {
        if (value == null || value.isEmpty()) return defaultValue;
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    public String getDisplayTimeZoneId() {
        return resolveDisplayZone(AuditLoggerConfiguration.get()).getId();
    }

    public String getDefaultViewMode() {
        return "all";
    }

    public String getDefaultDatePreset() {
        return computeDefaultDatePreset();
    }

    public String getDefaultDateFrom() {
        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        ZoneId displayZone = resolveDisplayZone(config);
        return computeDefaultDateFrom(LocalDate.now(displayZone));
    }

    public String getDefaultDateTo() {
        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        ZoneId displayZone = resolveDisplayZone(config);
        return computeDefaultDateTo(LocalDate.now(displayZone));
    }

    public boolean getStatsEnabled() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c != null && c.isEnableDashboardStats();
    }

    public boolean getCsvExportEnabled() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c != null && c.isEnableCsvExport();
    }

    public boolean getJsonExportEnabled() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c != null && c.isEnableJsonExport();
    }

    public boolean getRiskLevelsEnabled() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c != null && c.isEnableRiskLevels();
    }

    public boolean getAnomalyDetectionEnabled() {
        return false;
    }

    public boolean getAnomalyRowEnabled() {
        return false;
    }

    public String getAnomalyConfigJson() {
        return new com.google.gson.Gson().toJson(buildAnomalyConfig(AuditLoggerConfiguration.get()));
    }

    private static Map<String, Object> buildAnomalyConfig(AuditLoggerConfiguration config) {
        Map<String, Object> anomalyConfig = new LinkedHashMap<>();
        if (config == null) {
            anomalyConfig.put("failedLoginsThreshold", 5);
            anomalyConfig.put("credentialChangesThreshold", 3);
            anomalyConfig.put("pluginChangesThreshold", 3);
            anomalyConfig.put("globalConfigChangesThreshold", 5);
            anomalyConfig.put("jobConfigChangesThreshold", 1);
            anomalyConfig.put("securityConfigChangesThreshold", 1);
            anomalyConfig.put("buildFailuresThreshold", 5);
            return anomalyConfig;
        }

        anomalyConfig.put("failedLoginsThreshold", config.getAnomalyFailedLoginsThreshold());
        anomalyConfig.put("credentialChangesThreshold", config.getAnomalyCredentialChangesThreshold());
        anomalyConfig.put("pluginChangesThreshold", config.getAnomalyPluginChangesThreshold());
        anomalyConfig.put("globalConfigChangesThreshold", config.getAnomalyGlobalConfigChangesThreshold());
        anomalyConfig.put("jobConfigChangesThreshold", config.getAnomalyJobConfigChangesThreshold());
        anomalyConfig.put("securityConfigChangesThreshold", config.getAnomalySecurityConfigChangesThreshold());
        anomalyConfig.put("buildFailuresThreshold", config.getAnomalyBuildFailuresThreshold());
        return anomalyConfig;
    }

    public boolean getShowMetricTotal() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c == null || c.isShowMetricTotal();
    }

    public boolean getShowMetricLogins() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c == null || c.isShowMetricLogins();
    }

    public boolean getShowMetricFailedLogins() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c == null || c.isShowMetricFailedLogins();
    }

    public boolean getShowMetricBuilds() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c == null || c.isShowMetricBuilds();
    }

    public boolean getShowMetricJobs() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c == null || c.isShowMetricJobs();
    }

    public boolean getShowMetricConfig() {
        AuditLoggerConfiguration c = AuditLoggerConfiguration.get();
        return c == null || c.isShowMetricConfig();
    }

    /** Check if this is the first time the plugin has been opened (no logs yet). */
    public boolean getFirstRun() {
        return !AuditLogStorage.getInstance().hasEntries();
    }

    @GET
    public void doExportJson(StaplerRequest2 req, StaplerResponse2 res) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        AuditLoggerConfiguration cfg = AuditLoggerConfiguration.get();
        if (cfg != null && !cfg.isEnableJsonExport()) {
            res.setStatus(403);
            res.getWriter().write("{\"error\":\"JSON export is disabled in configuration\"}");
            return;
        }

        try {
            ZoneId displayZone = resolveDisplayZone(cfg);
            AuditViewRequest viewRequest = AuditViewRequest.fromRequest(req, displayZone);
            List<AuditLogEntry> entries = loadFilteredEntries(viewRequest, displayZone);

            if (entries.size() > MAX_EXPORT_ROWS) {
                entries = entries.subList(0, MAX_EXPORT_ROWS);
            }

            String filename = "auditflow-logs-" + LocalDate.now(displayZone) + ".json";
            res.setContentType("application/json; charset=UTF-8");
            res.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

            var gson = new com.google.gson.GsonBuilder()
                    .setPrettyPrinting()
                    .create();
            var response = new LinkedHashMap<String, Object>();
            response.put("total", entries.size());
            response.put("displayTimeZone", displayZone.getId());
            response.put("logs", toDisplayEntries(entries, displayZone));
            res.getWriter().write(gson.toJson(response));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in JSON export", e);
            res.getWriter().write("{\"error\":\"Internal server error\"}");
        }
    }

    @GET
    public void doExportTxt(StaplerRequest2 req, StaplerResponse2 res) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        try {
            AuditLoggerConfiguration cfg = AuditLoggerConfiguration.get();
            ZoneId displayZone = resolveDisplayZone(cfg);
            AuditViewRequest viewRequest = AuditViewRequest.fromRequest(req, displayZone);
            List<AuditLogEntry> entries = loadFilteredEntries(viewRequest, displayZone);

            if (entries.size() > MAX_EXPORT_ROWS) {
                entries = entries.subList(0, MAX_EXPORT_ROWS);
            }

            res.setContentType("text/plain; charset=UTF-8");
            res.setHeader("Content-Disposition", "attachment; filename=\"auditflow-logs.txt\"");

            try (var writer = res.getWriter()) {
                writer.println(String.format("%-24s %-15s %-28s %-25s %-40s %-18s %-15s %-10s",
                        "Timestamp", "User", "Action", "Target", "Details", "SourceIP", "AuthMethod", "Severity"));
                writer.println("=".repeat(180));
                for (AuditLogEntry entry : entries) {
                    writer.println(String.format("%-24s %-15s %-28s %-25s %-40s %-18s %-15s %-10s",
                            nvl(entry.getReadableTimestamp(displayZone)),
                            nvl(entry.getUsername()),
                            nvl(entry.getAction()),
                            nvl(entry.getTarget()),
                            truncate(nvl(entry.getDetails()), 40),
                            nvl(entry.getSourceIp()),
                            nvl(entry.getAuthMethod()),
                            nvl(entry.getSeverity())));
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in TXT export", e);
            res.getWriter().write("Error generating export");
        }
    }

    private static String nvl(String value) {
        return value == null ? "-" : value;
    }

    private static String truncate(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max - 3) + "...";
    }

    static List<AuditLogEntry> loadFilteredEntries(AuditViewRequest request, ZoneId displayZone) {
        List<AuditLogEntry> candidates = AuditLogStorage.getInstance()
                .filterEntries(null, request.action, request.startTime, request.endTime);
        return filterAndSortEntries(candidates, request, displayZone);
    }

    static List<AuditLogEntry> filterAndSortEntries(List<AuditLogEntry> candidates,
                                                    AuditViewRequest request,
                                                    ZoneId displayZone) {
        List<AuditLogEntry> filtered = new ArrayList<>();
        for (AuditLogEntry entry : candidates) {
            if (!matchesViewMode(entry, request.viewMode)) {
                continue;
            }
            if (!matchesSearch(entry, request.searchText, request.searchColumn, displayZone)) {
                continue;
            }
            filtered.add(entry);
        }

        Comparator<AuditLogEntry> comparator = buildComparator(request.sortField);
        if (request.sortAscending) {
            filtered.sort(comparator);
        } else {
            filtered.sort(comparator.reversed());
        }
        return filtered;
    }

    static PageSlice paginateEntries(List<AuditLogEntry> entries, int page, int pageSize) {
        if (pageSize <= 0 || entries.size() <= pageSize) {
            return new PageSlice(entries, 1, pageSize, 1);
        }

        int totalPages = (int) Math.ceil((double) entries.size() / (double) pageSize);
        int normalizedPage = Math.max(1, Math.min(page, totalPages));
        int start = (normalizedPage - 1) * pageSize;
        int end = Math.min(start + pageSize, entries.size());
        return new PageSlice(entries.subList(start, end), normalizedPage, pageSize, totalPages);
    }

    private static boolean matchesViewMode(AuditLogEntry entry, String viewMode) {
        if (!"user-only".equals(viewMode)) {
            return true;
        }

        if (!"SYSTEM".equalsIgnoreCase(entry.getUsername())) {
            return true;
        }

        String action = entry.getAction() != null ? entry.getAction() : "";
        return action.contains("BUILD") || action.contains("CREDENTIAL");
    }

    private static boolean matchesSearch(AuditLogEntry entry,
                                         String searchText,
                                         String searchColumn,
                                         ZoneId displayZone) {
        if (searchText == null || searchText.isEmpty()) {
            return true;
        }

        String needle = searchText.toLowerCase(Locale.ENGLISH);
        if ("all".equals(searchColumn)) {
            String haystack = String.join(" ",
                    nvl(entry.getUsername()),
                    nvl(entry.getAction()),
                    nvl(entry.getTarget()),
                    nvl(entry.getDetails()),
                    nvl(entry.getSourceIp()),
                    nvl(entry.getAuthMethod()),
                    nvl(entry.getTriggerType()),
                    entry.getReadableTimestamp(displayZone))
                    .toLowerCase(Locale.ENGLISH);
            return haystack.contains(needle);
        }

        String value;
        switch (searchColumn) {
            case "user":
                value = entry.getUsername();
                break;
            case "action":
                value = entry.getAction();
                break;
            case "target":
                value = entry.getTarget();
                break;
            case "details":
                value = entry.getDetails();
                break;
            case "sourceIp":
                value = entry.getSourceIp();
                break;
            case "authMethod":
                value = entry.getAuthMethod() != null ? entry.getAuthMethod() : entry.getTriggerType();
                break;
            default:
                value = "";
        }
        return value != null && value.toLowerCase(Locale.ENGLISH).contains(needle);
    }

    private static Comparator<AuditLogEntry> buildComparator(String sortField) {
        if (sortField == null || sortField.isEmpty() || "readable".equals(sortField) || "timestampMs".equals(sortField)) {
            return Comparator.comparingLong(AuditLogEntry::getTimestamp);
        }

        switch (sortField) {
            case "user":
                return Comparator.comparing(entry -> lower(entry.getUsername()));
            case "action":
                return Comparator.comparing(entry -> lower(entry.getAction()));
            case "target":
                return Comparator.comparing(entry -> lower(entry.getTarget()));
            case "sourceIp":
                return Comparator.comparing(entry -> lower(entry.getSourceIp()));
            default:
                return Comparator.comparingLong(AuditLogEntry::getTimestamp);
        }
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ENGLISH);
    }

    static Map<String, Object> buildSummary(List<AuditLogEntry> entries, ZoneId displayZone) {
        long now = System.currentTimeMillis();
        long last24Hours = now - DAY_MS;
        long todayStart = LocalDate.now(displayZone).atStartOfDay(displayZone).toInstant().toEpochMilli();

        int todayTotal = 0;
        int todayLogins = 0;
        int todayFailed = 0;
        int todayBuilds = 0;
        int todayJobs = 0;
        int todayConfig = 0;
        int riskFailed = 0;
        int riskCredentials = 0;
        Set<String> uniqueIps = new HashSet<>();

        for (AuditLogEntry entry : entries) {
            long timestamp = entry.getTimestamp();
            String action = entry.getAction() != null ? entry.getAction() : "";

            if (timestamp >= todayStart) {
                todayTotal++;
                if ("LOGIN".equals(action) || "API_AUTH".equals(action) || "SSO_LOGIN".equals(action)) {
                    todayLogins++;
                }
                if ("FAILED_LOGIN".equals(action)) {
                    todayFailed++;
                }
                if (action.contains("BUILD")) {
                    todayBuilds++;
                }
                if (action.contains("JOB")) {
                    todayJobs++;
                }
                if (action.contains("CONFIG") || action.contains("CREDENTIAL") || action.contains("PLUGIN")) {
                    todayConfig++;
                }
            }

            if (timestamp >= last24Hours) {
                if ("FAILED_LOGIN".equals(action)) {
                    riskFailed++;
                }
                if (action.contains("CREDENTIAL")) {
                    riskCredentials++;
                }
                if (entry.getSourceIp() != null && !entry.getSourceIp().isEmpty() && !"-".equals(entry.getSourceIp())) {
                    uniqueIps.add(entry.getSourceIp());
                }
            }
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("todayTotal", todayTotal);
        summary.put("todayLogins", todayLogins);
        summary.put("todayFailed", todayFailed);
        summary.put("todayBuilds", todayBuilds);
        summary.put("todayJobs", todayJobs);
        summary.put("todayConfig", todayConfig);
        summary.put("riskFailedCount", riskFailed);
        summary.put("riskCredentialCount", riskCredentials);
        summary.put("riskIpCount", uniqueIps.size());
        return summary;
    }

    static List<Map<String, Object>> buildInsights(List<AuditLogEntry> entries,
                                                   AuditLoggerConfiguration config,
                                                   ZoneId displayZone) {
        long todayStart = LocalDate.now(displayZone).atStartOfDay(displayZone).toInstant().toEpochMilli();

        int failedLogins = 0;
        int logins = 0;
        Map<String, Integer> buildFails = new HashMap<>();
        int credUpdates = 0;
        int credCreates = 0;
        int credDeletes = 0;
        int pluginChanges = 0;
        int jobDeletes = 0;
        int globalCfg = 0;
        int jobCfg = 0;
        int secCfg = 0;
        Map<String, Integer> topUsers = new HashMap<>();

        for (AuditLogEntry entry : entries) {
            if (entry.getTimestamp() < todayStart) {
                continue;
            }

            String action = entry.getAction() != null ? entry.getAction() : "";
            String user = entry.getUsername() != null ? entry.getUsername() : "";

            if ("FAILED_LOGIN".equals(action)) failedLogins++;
            if ("LOGIN".equals(action) || "SSO_LOGIN".equals(action) || "API_AUTH".equals(action)) logins++;
            if ("BUILD_FAILED".equals(action)) {
                String target = entry.getTarget() != null ? entry.getTarget() : "unknown";
                buildFails.put(target, buildFails.getOrDefault(target, 0) + 1);
            }
            if ("CREDENTIAL_UPDATED".equals(action)) credUpdates++;
            if ("CREDENTIAL_CREATED".equals(action)) credCreates++;
            if ("CREDENTIAL_DELETED".equals(action)) credDeletes++;
            if (action.startsWith("PLUGIN")) pluginChanges++;
            if ("JOB_DELETED".equals(action)) jobDeletes++;
            if ("GLOBAL_CONFIG_UPDATED".equals(action) || "SYS_CONFIG_UPDATED".equals(action)) globalCfg++;
            if ("JOB_CONFIG_UPDATED".equals(action)) jobCfg++;
            if ("SECURITY_CONFIG_UPDATED".equals(action) || "AUTH_STRATEGY_CHANGED".equals(action)) secCfg++;
            if (!user.isEmpty() && !"SYSTEM".equals(user)) {
                topUsers.put(user, topUsers.getOrDefault(user, 0) + 1);
            }
        }

        int failedLoginThreshold = config != null ? config.getAnomalyFailedLoginsThreshold() : 5;
        int credentialChangesThreshold = config != null ? config.getAnomalyCredentialChangesThreshold() : 3;
        int pluginChangesThreshold = config != null ? config.getAnomalyPluginChangesThreshold() : 3;
        int globalConfigChangesThreshold = config != null ? config.getAnomalyGlobalConfigChangesThreshold() : 5;
        int jobConfigChangesThreshold = config != null ? config.getAnomalyJobConfigChangesThreshold() : 1;
        int securityConfigChangesThreshold = config != null ? config.getAnomalySecurityConfigChangesThreshold() : 1;
        int buildFailuresThreshold = config != null ? config.getAnomalyBuildFailuresThreshold() : 5;

        List<Map<String, Object>> insights = new ArrayList<>();
        if (failedLogins > 0) {
            insights.add(insight("warning",
                    failedLogins >= failedLoginThreshold ? "Failed login spike" : "Failed login activity",
                    failedLogins,
                    failedLogins >= failedLoginThreshold ? "critical" : "medium"));
        }

        List<Map.Entry<String, Integer>> failedBuildEntries = new ArrayList<>(buildFails.entrySet());
        failedBuildEntries.sort((left, right) -> Integer.compare(right.getValue(), left.getValue()));
        for (int index = 0; index < Math.min(failedBuildEntries.size(), 3); index++) {
            Map.Entry<String, Integer> build = failedBuildEntries.get(index);
            insights.add(insight("alert",
                    build.getValue() + " failed build" + (build.getValue() > 1 ? "s" : "") + " (" + build.getKey() + ")",
                    build.getValue(),
                    build.getValue() >= buildFailuresThreshold ? "high" : "medium"));
        }

        int totalCreds = credUpdates + credCreates + credDeletes;
        if (totalCreds > 0) {
            List<String> credentialParts = new ArrayList<>();
            if (credCreates > 0) credentialParts.add(credCreates + " created");
            if (credUpdates > 0) credentialParts.add(credUpdates + " updated");
            if (credDeletes > 0) credentialParts.add(credDeletes + " deleted");
            insights.add(insight("key",
                    "Credential changes: " + String.join(", ", credentialParts),
                    totalCreds,
                    totalCreds >= credentialChangesThreshold ? "high" : "medium"));
        }

        if (secCfg > 0) {
            insights.add(insight("shield", "Security config changes", secCfg,
                    secCfg >= securityConfigChangesThreshold ? "critical" : "high"));
        }
        if (globalCfg > 0) {
            insights.add(insight("settings", "Global config changes", globalCfg,
                    globalCfg >= globalConfigChangesThreshold ? "high" : "low"));
        }
        if (jobCfg > 0) {
            insights.add(insight("document", "Job config changes", jobCfg,
                    jobCfg >= jobConfigChangesThreshold ? "high" : "medium"));
        }
        if (pluginChanges > 0) {
            insights.add(insight("cube", "Plugin changes", pluginChanges,
                    pluginChanges >= pluginChangesThreshold ? "high" : "medium"));
        }
        if (jobDeletes > 0) {
            insights.add(insight("trash", "Jobs deleted", jobDeletes,
                    jobDeletes >= 3 ? "critical" : "high"));
        }

        String topUser = null;
        int topCount = 0;
        for (Map.Entry<String, Integer> userEntry : topUsers.entrySet()) {
            if (userEntry.getValue() > topCount) {
                topUser = userEntry.getKey();
                topCount = userEntry.getValue();
            }
        }
        if (topUser != null) {
            insights.add(insight("person", "Most active: " + topUser, topCount, "low"));
        }
        if (logins > 0) {
            insights.add(insight("checkmark", "Successful logins", logins, "low"));
        }

        insights.sort((left, right) -> {
            int severityDiff = Integer.compare(insightSeverityWeight((String) right.get("severity")),
                    insightSeverityWeight((String) left.get("severity")));
            if (severityDiff != 0) {
                return severityDiff;
            }

            int countDiff = Integer.compare((Integer) right.get("count"), (Integer) left.get("count"));
            if (countDiff != 0) {
                return countDiff;
            }

            return ((String) left.get("text")).compareTo((String) right.get("text"));
        });

        if (insights.size() > 6) {
            return new ArrayList<>(insights.subList(0, 6));
        }
        return insights;
    }

    private static Map<String, Object> insight(String icon, String text, int count, String severity) {
        Map<String, Object> insight = new LinkedHashMap<>();
        insight.put("icon", icon);
        insight.put("text", text);
        insight.put("count", count);
        insight.put("severity", severity);
        return insight;
    }

    private static int insightSeverityWeight(String severity) {
        if ("critical".equals(severity)) return 4;
        if ("high".equals(severity)) return 3;
        if ("medium".equals(severity)) return 2;
        return 1;
    }

    static List<Map<String, Object>> toDisplayEntries(List<AuditLogEntry> entries, ZoneId displayZone) {
        List<Map<String, Object>> mappedEntries = new ArrayList<>(entries.size());
        for (AuditLogEntry entry : entries) {
            mappedEntries.add(toDisplayEntry(entry, displayZone));
        }
        return mappedEntries;
    }

    static Map<String, Object> toDisplayEntry(AuditLogEntry entry, ZoneId displayZone) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("timestamp", entry.getFormattedTimestamp());
        json.put("timestampMs", entry.getTimestamp());
        json.put("user", entry.getUsername());
        json.put("action", entry.getAction());
        json.put("target", entry.getTarget());
        json.put("details", entry.getDetails() != null ? entry.getDetails() : "");
        json.put("readable", entry.getReadableTimestamp(displayZone));
        json.put("sourceIp", entry.getSourceIp() != null ? entry.getSourceIp() : "");
        json.put("authMethod", entry.getAuthMethod() != null ? entry.getAuthMethod() : "");
        json.put("triggerType", entry.getTriggerType() != null ? entry.getTriggerType() : "");
        json.put("sessionId", entry.getSessionId() != null ? entry.getSessionId() : "");
        json.put("userAgent", entry.getUserAgent() != null ? entry.getUserAgent() : "");
        json.put("severity", entry.getSeverity() != null ? entry.getSeverity() : "INFO");
        return json;
    }

    private static ZoneId resolveDisplayZone(AuditLoggerConfiguration config) {
        try {
            return config != null ? config.getDisplayTimeZone() : ZoneOffset.UTC;
        } catch (Exception ignored) {
            return ZoneOffset.UTC;
        }
    }

    private static Long parseDateLowerBound(String date, ZoneId displayZone) {
        if (date == null || date.isEmpty()) {
            return null;
        }
        try {
            return LocalDate.parse(date).atStartOfDay(displayZone).toInstant().toEpochMilli();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static Long parseDateUpperBound(String date, ZoneId displayZone) {
        if (date == null || date.isEmpty()) {
            return null;
        }
        try {
            return LocalDate.parse(date).plusDays(1).atStartOfDay(displayZone).toInstant().toEpochMilli() - 1L;
        } catch (Exception ignored) {
            return null;
        }
    }

    static String computeDefaultDatePreset() {
        return "7d";
    }

    static String computeDefaultDateFrom(LocalDate today) {
        if (today == null) {
            return "";
        }
        return today.minusDays(6L).toString();
    }

    static String computeDefaultDateTo(LocalDate today) {
        if (today == null) {
            return "";
        }
        return today.toString();
    }

    static final class AuditViewRequest {
        final String searchText;
        final String searchColumn;
        final String action;
        final Long startTime;
        final Long endTime;
        final String viewMode;
        final String sortField;
        final boolean sortAscending;
        final int page;
        final int pageSize;

        AuditViewRequest(String searchText,
                         String searchColumn,
                         String action,
                         Long startTime,
                         Long endTime,
                         String viewMode,
                         String sortField,
                         boolean sortAscending,
                         int page,
                         int pageSize) {
            this.searchText = searchText;
            this.searchColumn = searchColumn;
            this.action = action;
            this.startTime = startTime;
            this.endTime = endTime;
            this.viewMode = viewMode;
            this.sortField = sortField;
            this.sortAscending = sortAscending;
            this.page = page;
            this.pageSize = pageSize;
        }

        static AuditViewRequest fromRequest(StaplerRequest2 req, ZoneId displayZone) {
            String searchText = trim(req.getParameter("searchText"));
            String searchColumn = trim(req.getParameter("searchColumn"));
            if (searchColumn == null || searchColumn.isEmpty()) {
                searchColumn = "all";
            }

            String action = trim(req.getParameter("action"));
            String viewMode = "all".equalsIgnoreCase(trim(req.getParameter("viewMode"))) ? "all" : "user-only";
            String sortField = trim(req.getParameter("sortField"));
            if (sortField == null || sortField.isEmpty()) {
                sortField = "timestampMs";
            }
            boolean sortAscending = "asc".equalsIgnoreCase(trim(req.getParameter("sortDir")));
            int page = Math.max(1, parseInt(req.getParameter("page"), 1));
            int pageSize = parseInt(req.getParameter("pageSize"), DEFAULT_PAGE_SIZE);
            if (pageSize < 0) {
                pageSize = DEFAULT_PAGE_SIZE;
            } else if (pageSize > MAX_PAGE_SIZE) {
                pageSize = MAX_PAGE_SIZE;
            }

            Long startTime = parseDateLowerBound(req.getParameter("dateFrom"), displayZone);
            if (startTime == null) {
                startTime = parseLong(req.getParameter("startTime"));
            }

            Long endTime = parseDateUpperBound(req.getParameter("dateTo"), displayZone);
            if (endTime == null) {
                endTime = parseLong(req.getParameter("endTime"));
            }

            return new AuditViewRequest(searchText, searchColumn, action, startTime, endTime,
                    viewMode, sortField, sortAscending, page, pageSize);
        }

        private static String trim(String value) {
            if (value == null) {
                return null;
            }
            String trimmed = value.trim();
            return trimmed.isEmpty() ? null : trimmed;
        }
    }

    static final class PageSlice {
        final List<AuditLogEntry> entries;
        final int page;
        final int pageSize;
        final int totalPages;

        PageSlice(List<AuditLogEntry> entries, int page, int pageSize, int totalPages) {
            this.entries = new ArrayList<>(entries);
            this.page = page;
            this.pageSize = pageSize;
            this.totalPages = totalPages;
        }
    }

    /** API endpoint for anomaly alerts, consumed by the dashboard's risk panel. */
    @GET
    public void doAlerts(StaplerRequest2 req, StaplerResponse2 res) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        try {
            AnomalyDetector detector = AuditLogStorage.getInstance().getAnomalyDetector();
            List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(50);

            var gson = new com.google.gson.GsonBuilder().create();
            var response = new LinkedHashMap<String, Object>();
            response.put("count", alerts.size());

            var alertList = new ArrayList<Map<String, Object>>();
            for (AnomalyDetector.AnomalyAlert alert : alerts) {
                var mappedAlert = new LinkedHashMap<String, Object>();
                mappedAlert.put("type", alert.type.name());
                mappedAlert.put("user", alert.user);
                mappedAlert.put("details", alert.details);
                mappedAlert.put("severity", alert.severity);
                mappedAlert.put("timestamp", alert.timestamp);
                alertList.add(mappedAlert);
            }
            response.put("alerts", alertList);

            res.setContentType("application/json; charset=UTF-8");
            res.getWriter().write(gson.toJson(response));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in alerts API", e);
            res.setContentType("application/json; charset=UTF-8");
            res.getWriter().write("{\"error\":\"Internal server error\",\"alerts\":[]}");
        }
    }
}
