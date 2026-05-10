package io.jenkins.plugins.auditlogger;

import org.htmlunit.FailingHttpStatusCodeException;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WithJenkins
class AuditLoggerManagementLinkApiToggleTest {

    @Test
    void apiEndpointHonorsConfigurationToggle(JenkinsRule j) {
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();
        configuration.setEnableAuditApi(false);

        JenkinsRule.WebClient webClient = j.createWebClient();
        FailingHttpStatusCodeException failure = assertThrows(FailingHttpStatusCodeException.class,
                () -> webClient.goTo("manage/auditflow-logs/api", "application/json"));

        assertEquals(403, failure.getStatusCode());
    }
}