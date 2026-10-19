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
    void cliCommandExecutionIsLoggedAndRegisteredInTracker(JenkinsRule j) {
        if (AuditLoggerConfiguration.get() == null) {
            j.getInstance().getExtensionList(AuditLoggerConfiguration.class).add(new AuditLoggerConfiguration());
        }
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);
        long startTime = System.currentTimeMillis();

        CLIContext context = new CLIContext("help", List.of("plugin"), null);
        new AuditCLIListener().onCompleted(context, 0);

        // Verify registration in AsyncActionTracker
        assertEquals("SYSTEM", AsyncActionTracker.getInstance().resolveUser("plugin", System.currentTimeMillis()));
        assertTrue(AuditLogStorage.getInstance().getAllEntries().stream().anyMatch(entry ->
                AuditCLIListener.CLI_EXECUTION_ACTION.equals(entry.getAction())
                        && "CLI: help".equals(entry.getTarget())
                        && "SYSTEM".equals(entry.getUsername())
                        && "LOW".equals(entry.getSeverity())
                        && entry.getDetails().contains("Exit Code: 0")
                        && entry.getDetails().contains("Args: [plugin]")),
                "Successful CLI execution should be recorded");
    }

    @Test
    void failedCliCommandExecutionIsLoggedWithUser(JenkinsRule j) {
        if (AuditLoggerConfiguration.get() == null) {
            j.getInstance().getExtensionList(AuditLoggerConfiguration.class).add(new AuditLoggerConfiguration());
        }
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);
        long startTime = System.currentTimeMillis();

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("alice", "password");
        CLIContext context = new CLIContext("install-plugin", List.of("ldap"), auth);
        new AuditCLIListener().onCompleted(context, 1);

        // Verify registration in AsyncActionTracker
        assertEquals("alice", AsyncActionTracker.getInstance().resolveUser("ldap", System.currentTimeMillis()));
        assertTrue(AuditLogStorage.getInstance().getAllEntries().stream().anyMatch(entry ->
                AuditCLIListener.CLI_EXECUTION_ACTION.equals(entry.getAction())
                        && "CLI: install-plugin".equals(entry.getTarget())
                        && "alice".equals(entry.getUsername())
                        && "MEDIUM".equals(entry.getSeverity())
                        && entry.getDetails().contains("Exit Code: 1")
                        && entry.getDetails().contains("Args: [ldap]")),
                "Failed CLI execution should be recorded with warning severity");
    }

    @Test
    void cliCommandExecutionIsIgnoredWhenSystemEventsDisabled(JenkinsRule j) {
        if (AuditLoggerConfiguration.get() == null) {
            j.getInstance().getExtensionList(AuditLoggerConfiguration.class).add(new AuditLoggerConfiguration());
        }
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(false);
        long startTime = System.currentTimeMillis();

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("bob", "password");
        CLIContext context = new CLIContext("help", List.of("ignored_plugin"), auth);
        new AuditCLIListener().onCompleted(context, 0);

        // AsyncActionTracker is a process-wide correlation cache shared by JenkinsRule
        // instances, so verify the externally observable audit-log behavior here.
        assertFalse(AuditLogStorage.getInstance().getAllEntries().stream().anyMatch(entry ->
                        AuditCLIListener.CLI_EXECUTION_ACTION.equals(entry.getAction())
                                && "CLI: help".equals(entry.getTarget())
                                && entry.getDetails().contains("ignored_plugin")),
                "Disabled system events must not record CLI executions");
    }
}
