package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

import java.io.Serializable;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Represents a single webhook destination (e.g., Slack channel, Microsoft Teams channel,
 * SIEM HTTP receiver) with fine-grained routing criteria including event scope,
 * minimum severity, and action label filters.
 */
public class WebhookEndpoint extends AbstractDescribableImpl<WebhookEndpoint> implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger.getLogger(WebhookEndpoint.class.getName());

    public static final String SCOPE_ALL = "ALL_ALERTS";
    public static final String SCOPE_ANOMALIES = "ANOMALIES_ONLY";
    public static final String SCOPE_CRITICAL_LOGS = "CRITICAL_LOGS_ONLY";

    private String id;
    private String name;
    private String channel;
    private Secret webhookUrl;
    private boolean enabled = true;
    private String scope = SCOPE_ALL;
    private String minSeverity = "HIGH";
    private String actionFilter = "";
    private Boolean notifyAuth = true;
    private Boolean notifySecurity = true;
    private Boolean notifyCredentials = true;
    private Boolean notifyJobs = true;
    private Boolean notifyNodes = true;
    private Boolean notifyAnomalies = true;

    @DataBoundConstructor
    public WebhookEndpoint(String name, Secret webhookUrl) {
        this.id = UUID.randomUUID().toString();
        this.name = name != null ? name.trim() : "";
        this.webhookUrl = webhookUrl;
        this.enabled = true;
        this.scope = SCOPE_ALL;
        this.minSeverity = "HIGH";
        this.actionFilter = "";
        this.notifyAuth = true;
        this.notifySecurity = true;
        this.notifyCredentials = true;
        this.notifyJobs = true;
        this.notifyNodes = true;
        this.notifyAnomalies = true;
    }

    public WebhookEndpoint(String name, String webhookUrl) {
        this(name, Secret.fromString(webhookUrl));
    }

    protected Object readResolve() {
        if (id == null || id.trim().isEmpty()) {
            id = UUID.randomUUID().toString();
        }
        if (scope == null || scope.trim().isEmpty()) {
            scope = SCOPE_ALL;
        }
        if (minSeverity == null || minSeverity.trim().isEmpty()) {
            minSeverity = "HIGH";
        }
        if (actionFilter == null) {
            actionFilter = "";
        }
        if (notifyAuth == null) notifyAuth = true;
        if (notifySecurity == null) notifySecurity = true;
        if (notifyCredentials == null) notifyCredentials = true;
        if (notifyJobs == null) notifyJobs = true;
        if (notifyNodes == null) notifyNodes = true;
        if (notifyAnomalies == null) notifyAnomalies = true;
        return this;
    }

    public String getId() {
        return id != null ? id : "";
    }

    @DataBoundSetter
    public void setId(String id) {
        this.id = (id != null && !id.trim().isEmpty()) ? id.trim() : UUID.randomUUID().toString();
    }

    public String getName() {
        return name != null ? name : "";
    }

    @DataBoundSetter
    public void setName(String name) {
        this.name = name != null ? name.trim() : "";
    }

    public String getChannel() {
        return channel != null ? channel : "";
    }

    @DataBoundSetter
    public void setChannel(String channel) {
        this.channel = channel != null ? channel.trim() : "";
    }

    public Secret getWebhookUrl() {
        return webhookUrl;
    }

    public String getPlainWebhookUrl() {
        return webhookUrl != null ? webhookUrl.getPlainText().trim() : "";
    }

    @DataBoundSetter
    public void setWebhookUrl(Secret webhookUrl) {
        this.webhookUrl = webhookUrl;
    }

    public boolean isEnabled() {
        return enabled;
    }

    @DataBoundSetter
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getScope() {
        return scope != null ? scope : SCOPE_ALL;
    }

    @DataBoundSetter
    public void setScope(String scope) {
        this.scope = (scope != null && !scope.trim().isEmpty()) ? scope.trim() : SCOPE_ALL;
    }

    public String getMinSeverity() {
        return minSeverity != null ? minSeverity : "HIGH";
    }

    @DataBoundSetter
    public void setMinSeverity(String minSeverity) {
        this.minSeverity = (minSeverity != null && !minSeverity.trim().isEmpty()) ? minSeverity.trim().toUpperCase(Locale.ENGLISH) : "HIGH";
    }

    public String getActionFilter() {
        return actionFilter != null ? actionFilter : "";
    }

    @DataBoundSetter
    public void setActionFilter(String actionFilter) {
        this.actionFilter = actionFilter != null ? actionFilter.trim() : "";
    }

    public boolean isNotifyAuth() {
        return notifyAuth != null ? notifyAuth : true;
    }

    @DataBoundSetter
    public void setNotifyAuth(boolean notifyAuth) {
        this.notifyAuth = notifyAuth;
    }

    public boolean isNotifySecurity() {
        return notifySecurity != null ? notifySecurity : true;
    }

    @DataBoundSetter
    public void setNotifySecurity(boolean notifySecurity) {
        this.notifySecurity = notifySecurity;
    }

    public boolean isNotifyCredentials() {
        return notifyCredentials != null ? notifyCredentials : true;
    }

    @DataBoundSetter
    public void setNotifyCredentials(boolean notifyCredentials) {
        this.notifyCredentials = notifyCredentials;
    }

    public boolean isNotifyJobs() {
        return notifyJobs != null ? notifyJobs : true;
    }

    @DataBoundSetter
    public void setNotifyJobs(boolean notifyJobs) {
        this.notifyJobs = notifyJobs;
    }

    public boolean isNotifyNodes() {
        return notifyNodes != null ? notifyNodes : true;
    }

    @DataBoundSetter
    public void setNotifyNodes(boolean notifyNodes) {
        this.notifyNodes = notifyNodes;
    }

    public boolean isNotifyAnomalies() {
        return notifyAnomalies != null ? notifyAnomalies : true;
    }

    @DataBoundSetter
    public void setNotifyAnomalies(boolean notifyAnomalies) {
        this.notifyAnomalies = notifyAnomalies;
    }

    /**
     * Determines whether this endpoint matches an event based on its enabled state,
     * configured scope, severity threshold, category filters, and optional action filter.
     *
     * @param eventType the event scope type: "ANOMALY" or "AUDIT_LOG" / "CRITICAL_LOG"
     * @param severity the event severity ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
     * @param action the specific action name (e.g. "SCRIPT_CONSOLE_ACCESS", "FAILED_LOGIN")
     * @return true if the event should be dispatched to this webhook endpoint
     */
    public boolean matches(String eventType, String severity, String action) {
        if (!enabled) {
            return false;
        }
        if (webhookUrl == null || webhookUrl.getPlainText().trim().isEmpty()) {
            return false;
        }

        // Scope check
        if (SCOPE_ANOMALIES.equalsIgnoreCase(scope)) {
            if (!"ANOMALY".equalsIgnoreCase(eventType)) {
                return false;
            }
        } else if (SCOPE_CRITICAL_LOGS.equalsIgnoreCase(scope)) {
            if ("ANOMALY".equalsIgnoreCase(eventType)) {
                return false;
            }
        }

        // Severity threshold check
        if (!isSeveritySatisfied(severity)) {
            return false;
        }

        // Tag / Included Events Filter check (unified OR-based evaluation)
        if (actionFilter != null && !actionFilter.trim().isEmpty()) {
            Set<String> tags = Arrays.stream(actionFilter.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(s -> s.toUpperCase(Locale.ENGLISH))
                    .collect(Collectors.toSet());

            if (!tags.isEmpty()) {
                String actUpper = action != null ? action.trim().toUpperCase(Locale.ENGLISH) : "";
                String normalizedAct = actUpper.startsWith("[CLI] ") ? actUpper.substring(6).trim() : actUpper;
                boolean matched = false;

                for (String tag : tags) {
                    if (tag.startsWith("CATEGORY:")) {
                        if (isCategoryTagMatched(tag, eventType, actUpper)) {
                            matched = true;
                            break;
                        }
                    } else if (!actUpper.isEmpty() && (actUpper.equals(tag) || normalizedAct.equals(tag))) {
                        matched = true;
                        break;
                    }
                }

                if (!matched) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Checks if a category tag (e.g. CATEGORY:AUTH, CATEGORY:SECURITY) matches the given event.
     */
    public static boolean isCategoryTagMatched(String tag, String eventType, String actionUpper) {
        if (tag == null) return false;
        String t = tag.trim().toUpperCase(Locale.ENGLISH);
        if ("CATEGORY:ANOMALIES".equals(t)) {
            return "ANOMALY".equalsIgnoreCase(eventType);
        }
        if ("ANOMALY".equalsIgnoreCase(eventType)) {
            return false;
        }

        switch (t) {
            case "CATEGORY:AUTH":
            case "CATEGORY:AUTHENTICATION":
                return actionUpper.contains("LOGIN") || actionUpper.contains("LOGOUT")
                        || actionUpper.contains("AUTH") || actionUpper.contains("SESSION");
            case "CATEGORY:SECURITY":
            case "CATEGORY:SYSTEM":
                return actionUpper.contains("SCRIPT") || actionUpper.contains("SECURITY")
                        || actionUpper.contains("RESTART") || actionUpper.contains("AUTH_STRATEGY")
                        || actionUpper.contains("USER_CONFIG") || actionUpper.contains("PRIVILEGE")
                        || actionUpper.contains("GLOBAL_CONFIG") || actionUpper.contains("USER_CREATED")
                        || actionUpper.contains("USER_DELETED") || actionUpper.contains("CLI_EXECUTION");
            case "CATEGORY:CREDENTIALS":
            case "CATEGORY:SECRETS":
                return actionUpper.contains("CREDENTIAL") || actionUpper.contains("SECRET");
            case "CATEGORY:JOBS":
            case "CATEGORY:BUILDS":
                return actionUpper.contains("JOB") || actionUpper.contains("BUILD")
                        || actionUpper.contains("PIPELINE");
            case "CATEGORY:NODES":
            case "CATEGORY:AGENTS":
                return actionUpper.contains("NODE") || actionUpper.contains("AGENT");
            default:
                return false;
        }
    }

    /**
     * Checks if the event category is enabled for this destination.
     */
    public boolean isCategorySatisfied(String eventType, String action) {
        if ("ANOMALY".equalsIgnoreCase(eventType)) {
            return isNotifyAnomalies();
        }
        if (action == null || action.trim().isEmpty()) {
            return true;
        }
        String u = action.trim().toUpperCase(Locale.ENGLISH);

        // Security / Admin
        if (u.contains("SCRIPT") || u.contains("SECURITY") || u.contains("RESTART")
                || u.contains("AUTH_STRATEGY") || u.contains("USER_CONFIG") || u.contains("PRIVILEGE")) {
            return isNotifySecurity();
        }
        // Authentication & Sessions
        if (u.contains("LOGIN") || u.contains("LOGOUT") || u.contains("AUTH") || u.contains("SESSION")) {
            return isNotifyAuth();
        }
        // Credentials
        if (u.contains("CREDENTIAL") || u.contains("SECRET")) {
            return isNotifyCredentials();
        }
        // Jobs & Builds
        if (u.contains("JOB") || u.contains("BUILD") || u.contains("PIPELINE")) {
            return isNotifyJobs();
        }
        // Nodes & Agents
        if (u.contains("NODE") || u.contains("AGENT")) {
            return isNotifyNodes();
        }

        return true;
    }

    /**
     * Evaluates if the event severity meets or exceeds the minimum severity threshold.
     */
    public boolean isSeveritySatisfied(String severity) {
        if (minSeverity == null || "ALL".equalsIgnoreCase(minSeverity.trim())) {
            return true;
        }
        int required = getSeverityScore(minSeverity);
        int actual = getSeverityScore(severity);
        return actual >= required;
    }

    public static int getSeverityScore(String severity) {
        if (severity == null) return 0;
        switch (severity.trim().toUpperCase(Locale.ENGLISH)) {
            case "CRITICAL": return 4;
            case "HIGH": return 3;
            case "MEDIUM": return 2;
            case "LOW": return 1;
            case "INFO":
            default: return 0;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebhookEndpoint that = (WebhookEndpoint) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<WebhookEndpoint> {
        @Override
        public String getDisplayName() {
            return "Webhook Destination Endpoint";
        }

        public ListBoxModel doFillScopeItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("All Alerts (Anomalies & Direct Audit Logs)", SCOPE_ALL);
            items.add("Anomaly Alerts Only", SCOPE_ANOMALIES);
            items.add("Direct Audit Logs Only", SCOPE_CRITICAL_LOGS);
            return items;
        }

        public ListBoxModel doFillMinSeverityItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("CRITICAL Only", "CRITICAL");
            items.add("HIGH and Above", "HIGH");
            items.add("MEDIUM and Above", "MEDIUM");
            items.add("LOW and Above", "LOW");
            items.add("ALL (including INFO)", "ALL");
            return items;
        }

        @POST
        public FormValidation doCheckName(
                @QueryParameter("value") String value,
                @QueryParameter("name") String name) {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins != null) {
                jenkins.checkPermission(Jenkins.ADMINISTER);
            }
            String target = (value != null && !value.trim().isEmpty()) ? value : name;
            if (target == null || target.trim().isEmpty()) {
                return FormValidation.error("Endpoint name cannot be empty.");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckWebhookUrl(
                @QueryParameter("value") String value,
                @QueryParameter("webhookUrl") String webhookUrl) {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins != null) {
                jenkins.checkPermission(Jenkins.ADMINISTER);
            }
            String raw = (value != null && !value.trim().isEmpty()) ? value : webhookUrl;
            if (raw == null || raw.trim().isEmpty()) {
                return FormValidation.error("Webhook URL cannot be empty.");
            }
            String plain = raw.trim();
            if (plain.startsWith("{") && plain.endsWith("}")) {
                try {
                    plain = Secret.fromString(plain).getPlainText().trim();
                } catch (Exception ignored) {
                }
            }
            if (plain.isEmpty()) {
                return FormValidation.error("Webhook URL cannot be empty.");
            }
            if (!plain.startsWith("http://") && !plain.startsWith("https://")) {
                return FormValidation.error("Webhook URL must start with http:// or https://");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doTestEndpoint(@QueryParameter("webhookUrl") Secret webhookUrl) {
            Jenkins jenkins = Jenkins.getInstanceOrNull();
            if (jenkins != null) {
                jenkins.checkPermission(Jenkins.ADMINISTER);
            }
            if (webhookUrl == null || webhookUrl.getPlainText().trim().isEmpty()) {
                return FormValidation.error("Webhook URL is empty. Please enter a valid URL to test.");
            }
            return testWebhookConnection(webhookUrl.getPlainText().trim());
        }
    }

    /**
     * Sends a harmless test payload to verify webhook connectivity and response.
     * Can be invoked by both endpoint test buttons and global single webhook test button.
     */
    public static FormValidation testWebhookConnection(String urlString) {
        if (urlString == null || urlString.trim().isEmpty()) {
            return FormValidation.error("Webhook URL is empty. Please enter a valid URL to test.");
        }
        String url = urlString.trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return FormValidation.error("Webhook URL must start with http:// or https://");
        }

        try {
            long nowSec = Instant.now().getEpochSecond();
            String testPayload = "{"
                    + "\"attachments\":[{"
                    + "\"color\":\"#2EB886\","
                    + "\"fallback\":\"[AuditFlow Test] Webhook endpoint test successful.\","
                    + "\"title\":\"\u2705 [AuditFlow] Webhook Endpoint Test Successful\","
                    + "\"fields\":["
                    + "{\"title\":\"Status\",\"value\":\"Connected\",\"short\":true},"
                    + "{\"title\":\"Source\",\"value\":\"Jenkins AuditFlow\",\"short\":true}"
                    + "],"
                    + "\"footer\":\"Jenkins AuditFlow Test\","
                    + "\"ts\":" + nowSec
                    + "}]"
                    + "}";

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(testPayload))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status >= 200 && status < 300) {
                return FormValidation.ok("Webhook test successful! (HTTP " + status + ")");
            } else {
                String snippet = response.body() != null && !response.body().trim().isEmpty()
                        ? ": " + response.body().trim()
                        : "";
                return FormValidation.error("Webhook endpoint returned HTTP " + status + snippet);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Webhook endpoint test failed for " + WebhookDispatcher.maskWebhookUrl(url), e);
            return FormValidation.error("Connection failed: " + e.getMessage());
        }
    }
}
