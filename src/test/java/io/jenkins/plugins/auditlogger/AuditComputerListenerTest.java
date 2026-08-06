package io.jenkins.plugins.auditlogger;

import hudson.model.Computer;
import hudson.model.TaskListener;
import hudson.slaves.DumbSlave;
import hudson.slaves.JNLPLauncher;
import hudson.slaves.OfflineCause;
import hudson.slaves.RetentionStrategy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditComputerListenerTest {

    @AfterEach
    void cleanup() {
        RequestHolder.clear();
        SecurityContextHolder.clearContext();
        try {
            AuditLogStorage.getInstance().shutdown();
        } catch (RuntimeException ignored) {}
        AuditLogStorage.clearInstance();
    }

    @Test
    void logsTemporarilyOfflineAndOnlineEventsWithUserAndCause(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration.get().setEnableNodeEvents(true);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin", "secret"));

        DumbSlave slave = new DumbSlave("agent-status-test", "dummy", "/tmp", "1", hudson.model.Node.Mode.NORMAL, "", new JNLPLauncher(), RetentionStrategy.NOOP, Collections.emptyList());
        j.jenkins.addNode(slave);
        Computer computer = slave.toComputer();

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        RequestHolder.setAuthenticatedUser("admin");
        computer.setTemporarilyOffline(false, null);
        StartupPhaseManager.resetRecentLogsForTests();

        computer.setTemporarilyOffline(true, new OfflineCause.UserCause(null, "Maintenance window"));
        computer.setTemporarilyOffline(false, null);

        List<AuditLogEntry> computerEvents = storage.getAllEntries().stream()
                .filter(entry -> entry.getTarget().equals("agent-status-test"))
                .filter(entry -> entry.getAction().equals("NODE_TEMPORARILY_OFFLINE") || entry.getAction().equals("NODE_ONLINE"))
                .toList();

        assertFalse(computerEvents.isEmpty(), "Should record computer temporarily offline/online events");
        
        AuditLogEntry offlineEntry = computerEvents.stream()
                .filter(e -> "NODE_TEMPORARILY_OFFLINE".equals(e.getAction()))
                .findFirst()
                .orElseThrow();
        assertEquals("admin", offlineEntry.getUsername());
        assertTrue(offlineEntry.getDetails().contains("Maintenance window"));

        AuditLogEntry onlineEntry = computerEvents.stream()
                .filter(e -> "NODE_ONLINE".equals(e.getAction()))
                .findFirst()
                .orElseThrow();
        assertEquals("admin", onlineEntry.getUsername());
    }

    @Test
    void logsNodeOnlineAndOfflineEvents(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration.get().setEnableNodeEvents(true);

        DumbSlave slave = new DumbSlave("agent-online-offline-test", "dummy", "/tmp", "1", hudson.model.Node.Mode.NORMAL, "", new JNLPLauncher(), RetentionStrategy.NOOP, Collections.emptyList());
        j.jenkins.addNode(slave);
        Computer computer = slave.toComputer();

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        AuditComputerListener listener = new AuditComputerListener();

        // Reset recent logs so manual invocation in unit test isn't deduplicated
        StartupPhaseManager.resetRecentLogsForTests();

        listener.onOnline(computer, TaskListener.NULL);
        listener.onOffline(computer, new OfflineCause.UserCause(null, "Disconnecting agent"));

        List<AuditLogEntry> events = storage.getAllEntries().stream()
                .filter(e -> e.getTarget().equals("agent-online-offline-test"))
                .filter(e -> "NODE_ONLINE".equals(e.getAction()) || "NODE_OFFLINE".equals(e.getAction()))
                .toList();

        assertFalse(events.isEmpty(), "Should capture online/offline events");
        assertTrue(events.stream().anyMatch(e -> "NODE_ONLINE".equals(e.getAction())));
        assertTrue(events.stream().anyMatch(e -> "NODE_OFFLINE".equals(e.getAction())));
    }
}
