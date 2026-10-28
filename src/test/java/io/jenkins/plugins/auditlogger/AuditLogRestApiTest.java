package io.jenkins.plugins.auditlogger;

import jenkins.model.Jenkins;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.Page;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditLogRestApiTest {

    @Test
    void testApiServesLogsWhenEnabledForAdmin(JenkinsRule j) throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER).everywhere().to("admin"));

        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        config.setEnableAuditApi(true);

        JenkinsRule.WebClient client = j.createWebClient().login("admin", "admin");
        Page page = client.goTo("auditflow/api", "application/json");

        assertEquals(200, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("\"status\": \"success\""));
    }

    @Test
    void testApiReturnsForbiddenWhenDisabled(JenkinsRule j) throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER).everywhere().to("admin"));

        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        config.setEnableAuditApi(false);

        JenkinsRule.WebClient client = j.createWebClient().login("admin", "admin");
        client.getOptions().setThrowExceptionOnFailingStatusCode(false);

        Page page = client.goTo("auditflow/api", "application/json");
        assertEquals(403, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("Audit API is disabled"));
    }

    @Test
    void testApiReturnsForbiddenForNonAdmin(JenkinsRule j) throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.READ).everywhere().to("alice"));

        JenkinsRule.WebClient client = j.createWebClient().login("alice", "alice");
        client.getOptions().setThrowExceptionOnFailingStatusCode(false);

        Page page = client.goTo("auditflow/api", "application/json");
        assertEquals(403, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("Admin permission required"));
    }
}

