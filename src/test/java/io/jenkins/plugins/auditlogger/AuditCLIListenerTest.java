package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import jenkins.cli.listeners.CLIContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditCLIListenerTest {
    @Test
    void cliCommandExecutionIsAudited(JenkinsRule j) {
        if (AuditLoggerConfiguration.get() == null) {
            j.getInstance().getExtensionList(AuditLoggerConfiguration.class).add(new AuditLoggerConfiguration());
        }
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);
        AuditLogStorage.clearInstance();
        AuditLogStorage.getInstance().initialize();
        long startTime = System.currentTimeMillis();

        CLIContext context = new CLIContext("help", List.of("plugin"), null);
        new AuditCLIListener().onCompleted(context, 0);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().filterEntries(
            null, AuditCLIListener.CLI_EXECUTION_ACTION, startTime, null);
        
        assertFalse(entries.isEmpty());
        AuditLogEntry latest = entries.get(entries.size() - 1);

        assertEquals(AuditCLIListener.CLI_EXECUTION_ACTION, latest.getAction());
        assertEquals("CLI: help", latest.getTarget());
        assertTrue(latest.getDetails().contains("CLI Command: help"));
        assertTrue(latest.getDetails().contains("Exit Code: 0"));
        assertTrue(latest.getDetails().contains("Args: [plugin]"));
        assertEquals("SYSTEM", latest.getUsername());
        assertEquals("LOW", latest.getSeverity());
    }

    @Test
    void cliCommandExecutionWithUserIsAudited(JenkinsRule j) {
        if (AuditLoggerConfiguration.get() == null) {
            j.getInstance().getExtensionList(AuditLoggerConfiguration.class).add(new AuditLoggerConfiguration());
        }
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);
        AuditLogStorage.clearInstance();
        AuditLogStorage.getInstance().initialize();
        long startTime = System.currentTimeMillis();

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("alice", "password");
        CLIContext context = new CLIContext("install-plugin", List.of("ldap"), auth);
        new AuditCLIListener().onCompleted(context, 1);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().filterEntries(
            null, AuditCLIListener.CLI_EXECUTION_ACTION, startTime, null);
        
        assertFalse(entries.isEmpty());
        AuditLogEntry latest = entries.get(entries.size() - 1);

        assertEquals(AuditCLIListener.CLI_EXECUTION_ACTION, latest.getAction());
        assertEquals("CLI: install-plugin", latest.getTarget());
        assertTrue(latest.getDetails().contains("CLI Command: install-plugin"));
        assertTrue(latest.getDetails().contains("Exit Code: 1"));
        assertTrue(latest.getDetails().contains("Args: [ldap]"));
        assertEquals("alice", latest.getUsername());
        assertEquals("MEDIUM", latest.getSeverity());

        // Verify registration in AsyncActionTracker
        assertEquals("alice", AsyncActionTracker.getInstance().resolveUser("ldap", System.currentTimeMillis()));
    }

    @Test
    void cliCommandExecutionIsIgnoredWhenSystemEventsDisabled(JenkinsRule j) {
        if (AuditLoggerConfiguration.get() == null) {
            j.getInstance().getExtensionList(AuditLoggerConfiguration.class).add(new AuditLoggerConfiguration());
        }
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(false);
        AuditLogStorage.clearInstance();
        AuditLogStorage.getInstance().initialize();
        long startTime = System.currentTimeMillis();

        CLIContext context = new CLIContext("help", List.of("plugin"), null);
        new AuditCLIListener().onCompleted(context, 0);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().filterEntries(
            null, AuditCLIListener.CLI_EXECUTION_ACTION, startTime, null);
        
        assertTrue(entries.isEmpty());
    }

    @Test
    void cliCommandExecutionHighSeverity(JenkinsRule j) {
        if (AuditLoggerConfiguration.get() == null) {
            j.getInstance().getExtensionList(AuditLoggerConfiguration.class).add(new AuditLoggerConfiguration());
        }
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);
        AuditLogStorage.clearInstance();
        AuditLogStorage.getInstance().initialize();
        long startTime = System.currentTimeMillis();

        CLIContext context = new CLIContext("delete-job", List.of("my-job"), null);
        new AuditCLIListener().onCompleted(context, 0);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().filterEntries(
            null, AuditCLIListener.CLI_EXECUTION_ACTION, startTime, null);
        
        assertFalse(entries.isEmpty());
        AuditLogEntry latest = entries.get(entries.size() - 1);
        assertEquals("HIGH", latest.getSeverity());
    }
}
