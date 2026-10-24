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
    }

    @Test
    void testDescriptorFormValidationAndOptions(JenkinsRule j) {
        WebhookEndpoint.DescriptorImpl desc = new WebhookEndpoint.DescriptorImpl();

        assertEquals(FormValidation.Kind.ERROR, desc.doCheckName("").kind);
        assertEquals(FormValidation.Kind.OK, desc.doCheckName("Valid Name").kind);

        assertEquals(FormValidation.Kind.ERROR, desc.doCheckWebhookUrl("").kind);
        assertEquals(FormValidation.Kind.ERROR, desc.doCheckWebhookUrl("ftp://invalid.com").kind);
        assertEquals(FormValidation.Kind.OK, desc.doCheckWebhookUrl("https://hooks.slack.com/123").kind);
        assertEquals(FormValidation.Kind.OK, desc.doCheckWebhookUrl("http://localhost:8080/hook").kind);

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
}
