package io.jenkins.plugins.auditlogger;

import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class WebhookEndpointTest {

    @Test
    void testBasicPropertiesAndDefaults(JenkinsRule j) {
        WebhookEndpoint ep = new WebhookEndpoint("SecOps Slack", "https://hooks.slack.com/services/T00/B00/XXX");
        assertEquals("SecOps Slack", ep.getName());
        assertEquals("https://hooks.slack.com/services/T00/B00/XXX", ep.getPlainWebhookUrl());
        assertTrue(ep.isEnabled());
        assertEquals(WebhookEndpoint.SCOPE_ALL, ep.getScope());
        assertEquals("HIGH", ep.getMinSeverity());
        assertEquals("", ep.getActionFilter());
        assertNotNull(ep.getId());
        assertFalse(ep.getId().isEmpty());

        ep.setChannel("#secops");
        assertEquals("#secops", ep.getChannel());

        ep.setId("custom-id-123");
        assertEquals("custom-id-123", ep.getId());
    }

    @Test
    void testSeverityEvaluation(JenkinsRule j) {
        WebhookEndpoint ep = new WebhookEndpoint("Test", "https://example.com/webhook");

        ep.setMinSeverity("CRITICAL");
        assertTrue(ep.isSeveritySatisfied("CRITICAL"));
        assertFalse(ep.isSeveritySatisfied("HIGH"));
        assertFalse(ep.isSeveritySatisfied("MEDIUM"));
        assertFalse(ep.isSeveritySatisfied("LOW"));
        assertFalse(ep.isSeveritySatisfied("INFO"));

        ep.setMinSeverity("HIGH");
        assertTrue(ep.isSeveritySatisfied("CRITICAL"));
        assertTrue(ep.isSeveritySatisfied("HIGH"));
        assertFalse(ep.isSeveritySatisfied("MEDIUM"));

        ep.setMinSeverity("MEDIUM");
        assertTrue(ep.isSeveritySatisfied("CRITICAL"));
        assertTrue(ep.isSeveritySatisfied("HIGH"));
        assertTrue(ep.isSeveritySatisfied("MEDIUM"));
        assertFalse(ep.isSeveritySatisfied("LOW"));

        ep.setMinSeverity("LOW");
        assertTrue(ep.isSeveritySatisfied("LOW"));
        assertFalse(ep.isSeveritySatisfied("INFO"));

        ep.setMinSeverity("ALL");
        assertTrue(ep.isSeveritySatisfied("INFO"));
        assertTrue(ep.isSeveritySatisfied("UNKNOWN"));
    }

    @Test
    void testMatchingLogic(JenkinsRule j) {
        WebhookEndpoint ep = new WebhookEndpoint("Alerts", "https://example.com/webhook");
        ep.setEnabled(true);
        ep.setScope(WebhookEndpoint.SCOPE_ALL);
        ep.setMinSeverity("HIGH");

        // 1. Matches under default settings
        assertTrue(ep.matches("ANOMALY", "HIGH", "FAILED_LOGINS"));
        assertTrue(ep.matches("AUDIT_LOG", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));
        assertFalse(ep.matches("ANOMALY", "MEDIUM", "FAILED_LOGINS"));

        // 2. Disabled check
        ep.setEnabled(false);
        assertFalse(ep.matches("ANOMALY", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));
        ep.setEnabled(true);

        // 3. Null / empty URL check
        ep.setWebhookUrl(Secret.fromString(""));
        assertFalse(ep.matches("ANOMALY", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));
        ep.setWebhookUrl(Secret.fromString("https://example.com/webhook"));

        // 4. Scope ANOMALIES_ONLY
        ep.setScope(WebhookEndpoint.SCOPE_ANOMALIES);
        assertTrue(ep.matches("ANOMALY", "HIGH", "FAILED_LOGINS"));
        assertFalse(ep.matches("AUDIT_LOG", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));

        // 5. Scope CRITICAL_LOGS_ONLY
        ep.setScope(WebhookEndpoint.SCOPE_CRITICAL_LOGS);
        assertFalse(ep.matches("ANOMALY", "HIGH", "FAILED_LOGINS"));
        assertTrue(ep.matches("AUDIT_LOG", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));

        // 6. Action Filter
        ep.setScope(WebhookEndpoint.SCOPE_ALL);
        ep.setActionFilter("SCRIPT_CONSOLE_ACCESS, SYSTEM_RESTART");
        assertTrue(ep.matches("AUDIT_LOG", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));
        assertTrue(ep.matches("AUDIT_LOG", "CRITICAL", "SYSTEM_RESTART"));
        assertFalse(ep.matches("AUDIT_LOG", "CRITICAL", "USER_DELETED"));
        assertFalse(ep.matches("AUDIT_LOG", "CRITICAL", null));

        // 7. Category Tags and Mixed Filters
        ep.setActionFilter("CATEGORY:SECURITY");
        assertTrue(ep.matches("AUDIT_LOG", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));
        assertFalse(ep.matches("AUDIT_LOG", "CRITICAL", "FAILED_LOGIN"));

        ep.setActionFilter("CATEGORY:AUTH");
        assertTrue(ep.matches("AUDIT_LOG", "CRITICAL", "FAILED_LOGIN"));
        assertFalse(ep.matches("AUDIT_LOG", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));

        // Mixed Category and specific action: CATEGORY:AUTH + SCRIPT_CONSOLE_ACCESS
        ep.setActionFilter("CATEGORY:AUTH, SCRIPT_CONSOLE_ACCESS");
        assertTrue(ep.matches("AUDIT_LOG", "CRITICAL", "FAILED_LOGIN"));
        assertTrue(ep.matches("AUDIT_LOG", "CRITICAL", "LOGIN"));
        assertTrue(ep.matches("AUDIT_LOG", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));
        assertFalse(ep.matches("AUDIT_LOG", "CRITICAL", "JOB_DELETED"));

        // Anomaly category tag
        ep.setActionFilter("CATEGORY:ANOMALIES");
        assertTrue(ep.matches("ANOMALY", "HIGH", "FAILED_LOGINS"));
        assertFalse(ep.matches("AUDIT_LOG", "CRITICAL", "SCRIPT_CONSOLE_ACCESS"));

        // Specific anomaly type tag
        ep.setActionFilter("BRUTE_FORCE_LOGIN");
        assertTrue(ep.matches("ANOMALY", "HIGH", "BRUTE_FORCE_LOGIN"));
        assertFalse(ep.matches("ANOMALY", "HIGH", "MULTI_IP_LOGIN"));

        ep.setActionFilter("CATEGORY:CREDENTIALS");
        assertTrue(ep.matches("AUDIT_LOG", "HIGH", "CREDENTIAL_DELETED"));
        assertFalse(ep.matches("AUDIT_LOG", "HIGH", "JOB_DELETED"));

        ep.setActionFilter("CATEGORY:JOBS");
        assertTrue(ep.matches("AUDIT_LOG", "HIGH", "JOB_DELETED"));
        assertFalse(ep.matches("AUDIT_LOG", "HIGH", "NODE_OFFLINE"));

        ep.setActionFilter("CATEGORY:NODES");
        assertTrue(ep.matches("AUDIT_LOG", "HIGH", "NODE_OFFLINE"));
        assertFalse(ep.matches("AUDIT_LOG", "HIGH", "JOB_DELETED"));
    }

    @Test
    void testDescriptorFormValidationAndOptions(JenkinsRule j) {
        WebhookEndpoint.DescriptorImpl desc = new WebhookEndpoint.DescriptorImpl();

        assertEquals(FormValidation.Kind.ERROR, desc.doCheckName("", null).kind);
        assertEquals(FormValidation.Kind.ERROR, desc.doCheckName(null, "").kind);
        assertEquals(FormValidation.Kind.OK, desc.doCheckName("Valid Name", null).kind);
        assertEquals(FormValidation.Kind.OK, desc.doCheckName(null, "Valid Name").kind);

        assertEquals(FormValidation.Kind.ERROR, desc.doCheckWebhookUrl("", null).kind);
        assertEquals(FormValidation.Kind.ERROR, desc.doCheckWebhookUrl(null, "").kind);
        assertEquals(FormValidation.Kind.ERROR, desc.doCheckWebhookUrl("ftp://invalid.com", null).kind);
        assertEquals(FormValidation.Kind.ERROR, desc.doCheckWebhookUrl(null, "ftp://invalid.com").kind);
        assertEquals(FormValidation.Kind.OK, desc.doCheckWebhookUrl("https://hooks.slack.com/123", null).kind);
        assertEquals(FormValidation.Kind.OK, desc.doCheckWebhookUrl(null, "https://hooks.slack.com/123").kind);
        assertEquals(FormValidation.Kind.OK, desc.doCheckWebhookUrl("http://localhost:8080/hook", null).kind);

        hudson.util.Secret secret = hudson.util.Secret.fromString("https://hooks.slack.com/secret");
        assertEquals(FormValidation.Kind.OK, desc.doCheckWebhookUrl(secret.getEncryptedValue(), null).kind);
        assertEquals(FormValidation.Kind.OK, desc.doCheckWebhookUrl(null, secret.getEncryptedValue()).kind);

        ListBoxModel scopes = desc.doFillScopeItems();
        assertNotNull(scopes);
        assertTrue(scopes.size() >= 3);

        ListBoxModel severities = desc.doFillMinSeverityItems();
        assertNotNull(severities);
        assertTrue(severities.size() >= 5);
    }

    @Test
    void testEqualsAndHashCode(JenkinsRule j) {
        WebhookEndpoint ep1 = new WebhookEndpoint("Name1", "https://example.com/1");
        ep1.setId("fixed-id");
        WebhookEndpoint ep2 = new WebhookEndpoint("Name2", "https://example.com/2");
        ep2.setId("fixed-id");
        WebhookEndpoint ep3 = new WebhookEndpoint("Name3", "https://example.com/3");
        ep3.setId("other-id");

        assertEquals(ep1, ep2);
        assertEquals(ep1.hashCode(), ep2.hashCode());
        assertNotEquals(ep1, ep3);
    }

    @Test
    void testCheckWebhookUrlViaWebClient(JenkinsRule j) throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();

        // 1. Valid with parameter 'value'
        java.net.URL urlValue = new java.net.URL(j.getURL(), "descriptorByName/io.jenkins.plugins.auditlogger.WebhookEndpoint/checkWebhookUrl?value=" + java.net.URLEncoder.encode("https://hooks.slack.com/123", java.nio.charset.StandardCharsets.UTF_8));
        org.htmlunit.WebResponse resp1 = wc.getPage(new org.htmlunit.WebRequest(urlValue, org.htmlunit.HttpMethod.GET)).getWebResponse();
        assertEquals("<div/>", resp1.getContentAsString().trim());

        // 2. Valid with parameter 'webhookUrl'
        java.net.URL urlWebhookUrl = new java.net.URL(j.getURL(), "descriptorByName/io.jenkins.plugins.auditlogger.WebhookEndpoint/checkWebhookUrl?webhookUrl=" + java.net.URLEncoder.encode("https://hooks.slack.com/123", java.nio.charset.StandardCharsets.UTF_8));
        org.htmlunit.WebResponse resp2 = wc.getPage(new org.htmlunit.WebRequest(urlWebhookUrl, org.htmlunit.HttpMethod.GET)).getWebResponse();
        assertEquals("<div/>", resp2.getContentAsString().trim());

        // 3. Invalid format with parameter 'webhookUrl'
        java.net.URL urlInvalid = new java.net.URL(j.getURL(), "descriptorByName/io.jenkins.plugins.auditlogger.WebhookEndpoint/checkWebhookUrl?webhookUrl=invalid");
        org.htmlunit.WebResponse resp3 = wc.getPage(new org.htmlunit.WebRequest(urlInvalid, org.htmlunit.HttpMethod.GET)).getWebResponse();
        assertTrue(resp3.getContentAsString().contains("Webhook URL must start with http:// or https://"));

        // 4. Empty with parameter 'webhookUrl'
        java.net.URL urlEmpty = new java.net.URL(j.getURL(), "descriptorByName/io.jenkins.plugins.auditlogger.WebhookEndpoint/checkWebhookUrl?webhookUrl=");
        org.htmlunit.WebResponse resp4 = wc.getPage(new org.htmlunit.WebRequest(urlEmpty, org.htmlunit.HttpMethod.GET)).getWebResponse();
        assertTrue(resp4.getContentAsString().contains("Webhook URL cannot be empty."));
    }
}
