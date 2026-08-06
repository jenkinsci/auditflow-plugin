package io.jenkins.plugins.auditlogger;

import hudson.slaves.DumbSlave;
import hudson.slaves.JNLPLauncher;
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

        DumbSlave node = new DumbSlave("audit-agent", "dummy", "/tmp", "1", hudson.model.Node.Mode.NORMAL, "", new JNLPLauncher(), RetentionStrategy.NOOP, Collections.emptyList());
        j.jenkins.addNode(node);
        String nodeName = node.getNodeName();
        node.setNumExecutors(2);
        j.jenkins.updateNode(node);
        j.jenkins.removeNode(node);

        List<AuditLogEntry> nodeEvents = storage.getAllEntries().stream()
                .filter(entry -> List.of("NODE_CREATED", "NODE_UPDATED", "NODE_DELETED").contains(entry.getAction()))
                .filter(entry -> nodeName.equals(entry.getTarget()))
                .toList();

        assertEquals(List.of("NODE_CREATED", "NODE_UPDATED", "NODE_DELETED"),
                nodeEvents.stream().map(AuditLogEntry::getAction).toList());
        assertTrue(nodeEvents.stream().allMatch(entry -> "admin".equals(entry.getUsername())));
        assertTrue(nodeEvents.stream().allMatch(entry -> nodeName.equals(entry.getTarget())));
    }

    @Test
    void logsNodeEventsWithPreChainAuthenticatedUser(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration.get().setEnableNodeEvents(true);
        RequestHolder.setAuthenticatedUser("admin");

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        DumbSlave node = new DumbSlave("pre-chain-agent", "dummy", "/tmp", "1", hudson.model.Node.Mode.NORMAL, "", new JNLPLauncher(), RetentionStrategy.NOOP, Collections.emptyList());
        j.jenkins.addNode(node);
        String nodeName = node.getNodeName();

        List<AuditLogEntry> nodeEvents = storage.getAllEntries().stream()
                .filter(entry -> "NODE_CREATED".equals(entry.getAction()) && nodeName.equals(entry.getTarget()))
                .toList();

        assertEquals(1, nodeEvents.size());
        assertEquals("NODE_CREATED", nodeEvents.get(0).getAction());
        assertEquals("admin", nodeEvents.get(0).getUsername());
    }

    @Test
    void nodeSavesDoNotProduceGlobalConfigUpdated(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration.get().setEnableNodeEvents(true);
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin", "secret"));

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        DumbSlave node = new DumbSlave("test-node-save", "dummy", "/tmp", "1", hudson.model.Node.Mode.NORMAL, "", new JNLPLauncher(), RetentionStrategy.NOOP, Collections.emptyList());
        j.jenkins.addNode(node);
        node.save();

        List<AuditLogEntry> globalEvents = storage.getAllEntries().stream()
                .filter(entry -> "GLOBAL_CONFIG_UPDATED".equals(entry.getAction()) && entry.getTarget().contains("Slave"))
                .toList();

        assertTrue(globalEvents.isEmpty(), "Node saves should not be misclassified as GLOBAL_CONFIG_UPDATED");
    }

    @Test
    void logsNodeCreationWhenSecurityContextIsSystemButHttpRequestIsActive(JenkinsRule j) throws Exception {
        AuditLoggerConfiguration.get().setEnableNodeEvents(true);
        
        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        // Mock active HTTP request with authenticated user via proxy
        jakarta.servlet.http.HttpServletRequest req = (jakarta.servlet.http.HttpServletRequest) java.lang.reflect.Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(),
                new Class<?>[]{jakarta.servlet.http.HttpServletRequest.class},
                (proxy, method, args) -> {
                    if ("getHeader".equals(method.getName()) && args != null && args.length == 1 && "Authorization".equals(args[0])) {
                        return "Basic " + java.util.Base64.getEncoder().encodeToString("admin:pass".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    }
                    return null;
                });
        RequestHolder.set(req);

        // SecurityContext impersonated as SYSTEM (simulating ACL.as2)
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("SYSTEM", "system"));

        DumbSlave node = new DumbSlave("system-impersonated-agent", "dummy", "/tmp", "1", hudson.model.Node.Mode.NORMAL, "", new JNLPLauncher(), RetentionStrategy.NOOP, Collections.emptyList());
        j.jenkins.addNode(node);
        String nodeName = node.getNodeName();

        List<AuditLogEntry> nodeEvents = storage.getAllEntries().stream()
                .filter(entry -> "NODE_CREATED".equals(entry.getAction()) && nodeName.equals(entry.getTarget()))
                .toList();

        assertEquals(1, nodeEvents.size());
        assertEquals("NODE_CREATED", nodeEvents.get(0).getAction());
        assertEquals("admin", nodeEvents.get(0).getUsername());
    }
}
