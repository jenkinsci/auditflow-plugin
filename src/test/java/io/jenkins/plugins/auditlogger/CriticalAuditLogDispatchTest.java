package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class CriticalAuditLogDispatchTest {

    @Test
    void testDirectCriticalAuditLogDispatch(JenkinsRule j) {
        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        config.setEnableWebhookAlerts(true);
        config.setEnableMultiWebhook(true);

        WebhookEndpoint secops = new WebhookEndpoint("SecOps Pager", "https://hooks.slack.com/services/T0/B0/SECOPS");
        secops.setScope("CRITICAL_LOGS_ONLY");
        secops.setMinSeverity("CRITICAL");
        secops.setActionFilter("SCRIPT_CONSOLE_ACCESS");

        WebhookEndpoint devops = new WebhookEndpoint("DevOps General", "https://hooks.slack.com/services/T0/B0/DEVOPS");
        devops.setScope("ALL_ALERTS");
        devops.setMinSeverity("HIGH");

        config.setWebhookEndpoints(List.of(secops, devops));

        AuditLogStorage storage = AuditLogStorage.getInstance();

        // 1. Critical Script Console Event - should match both secops and devops
        AuditLogEntry scriptEntry = new AuditLogEntry("alice", "SCRIPT_CONSOLE_ACCESS", "RemotingDiagnostics", "println('test')");
        scriptEntry.setSeverity("CRITICAL");

        assertDoesNotThrow(() -> storage.addEntry(scriptEntry));

        List<WebhookEndpoint> matched = config.resolveActiveEndpoints("AUDIT_LOG", scriptEntry.getSeverity(), scriptEntry.getAction());
        assertEquals(2, matched.size());
        assertTrue(matched.stream().anyMatch(e -> "SecOps Pager".equals(e.getName())));
        assertTrue(matched.stream().anyMatch(e -> "DevOps General".equals(e.getName())));

        // 2. High severity Job deleted event - should match devops only (because action is not SCRIPT_CONSOLE_ACCESS)
        AuditLogEntry jobEntry = new AuditLogEntry("bob", "JOB_DELETED", "my-job", "deleted");
        jobEntry.setSeverity("HIGH");

        assertDoesNotThrow(() -> storage.addEntry(jobEntry));

        List<WebhookEndpoint> jobMatched = config.resolveActiveEndpoints("AUDIT_LOG", jobEntry.getSeverity(), jobEntry.getAction());
        assertEquals(1, jobMatched.size());
        assertEquals("DevOps General", jobMatched.get(0).getName());

        // 3. Info severity event - should match neither (below HIGH/CRITICAL)
        AuditLogEntry infoEntry = new AuditLogEntry("charlie", "VIEW_CONFIG", "System", "viewed");
        infoEntry.setSeverity("INFO");

        assertDoesNotThrow(() -> storage.addEntry(infoEntry));

        List<WebhookEndpoint> infoMatched = config.resolveActiveEndpoints("AUDIT_LOG", infoEntry.getSeverity(), infoEntry.getAction());
        assertEquals(0, infoMatched.size());
    }
}
