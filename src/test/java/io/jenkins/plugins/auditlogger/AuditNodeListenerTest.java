package io.jenkins.plugins.auditlogger;

import hudson.slaves.DumbSlave;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditNodeListenerTest {

    @AfterEach
    void cleanup() {
        RequestHolder.clear();
        SecurityContextHolder.clearContext();
        try {
            AuditLogStorage.getInstance().shutdown();
        } catch (RuntimeException ignored) {
            // Best-effort cleanup for isolated test storage.
        }
        AuditLogStorage.clearInstance();
    }

    @Test
    void logsNodeCreationModificationAndDeletionWithTheInitiatingUser(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration.get().setEnableNodeEvents(true);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin", "secret"));

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        DumbSlave node = j.createSlave("audit-agent", new hudson.EnvVars());
        String nodeName = node.getNodeName();
        node.setNumExecutors(2);
        j.jenkins.updateNode(node);
        j.jenkins.removeNode(node);

        List<AuditLogEntry> nodeEvents = storage.getAllEntries().stream()
                .filter(entry -> entry.getAction().startsWith("NODE_"))
                .toList();

        assertEquals(List.of("NODE_CREATED", "NODE_UPDATED", "NODE_DELETED"),
                nodeEvents.stream().map(AuditLogEntry::getAction).toList());
        assertTrue(nodeEvents.stream().allMatch(entry -> "admin".equals(entry.getUsername())));
        assertTrue(nodeEvents.stream().allMatch(entry -> nodeName.equals(entry.getTarget())));
    }
}
