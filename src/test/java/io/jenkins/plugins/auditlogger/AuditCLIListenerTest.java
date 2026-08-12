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
    void cliCommandExecutionIsRegisteredInTracker(JenkinsRule j) {
        if (AuditLoggerConfiguration.get() == null) {
            j.getInstance().getExtensionList(AuditLoggerConfiguration.class).add(new AuditLoggerConfiguration());
        }
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);
        long startTime = System.currentTimeMillis();

        CLIContext context = new CLIContext("help", List.of("plugin"), null);
        new AuditCLIListener().onCompleted(context, 0);

        // Verify registration in AsyncActionTracker
        assertEquals("SYSTEM", AsyncActionTracker.getInstance().resolveUser("plugin", System.currentTimeMillis()));
    }

    @Test
    void cliCommandExecutionWithUserIsRegistered(JenkinsRule j) {
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

        // Tracker should return null as it was ignored
        assertEquals(null, AsyncActionTracker.getInstance().resolveUser("ignored_plugin", System.currentTimeMillis()));
    }
}
