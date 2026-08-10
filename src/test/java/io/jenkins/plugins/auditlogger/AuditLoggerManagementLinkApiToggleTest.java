package io.jenkins.plugins.auditlogger;

import org.htmlunit.Page;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@WithJenkins
class AuditLoggerManagementLinkApiToggleTest {

    @Test
    void apiEndpointIsEnabledByDefault(JenkinsRule j) throws Exception {
        JenkinsRule.WebClient webClient = j.createWebClient();
        Page page = webClient.goTo("manage/auditflow-logs/api", "application/json");

        assertEquals(200, page.getWebResponse().getStatusCode());
        assertNotNull(page.getWebResponse().getContentAsString());
    }
}