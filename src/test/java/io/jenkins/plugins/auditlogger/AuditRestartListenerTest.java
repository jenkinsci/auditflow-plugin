package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditRestartListenerTest {

    @AfterEach
    void cleanup() {
        RequestHolder.clear();
        RequestHolder.clearPendingSafeRestartInitiator();
        SecurityContextHolder.clearContext();
        try {
            AuditLogStorage.getInstance().shutdown();
        } catch (RuntimeException ignored) {
            // Best-effort cleanup for isolated test storage.
        }
        AuditLogStorage.clearInstance();
    }

    @Test
    void onRestartLogsImmediateRestartEvent(JenkinsRule j) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("harry", "secret"));

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        new AuditRestartListener().onRestart();

        List<AuditLogEntry> entries = storage.getAllEntries();
        AuditLogEntry restartEntry = entries.stream()
                .filter(entry -> "SYSTEM_RESTART".equals(entry.getAction()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing SYSTEM_RESTART audit entry"));

        assertEquals("harry", restartEntry.getUsername());
        assertEquals("Jenkins", restartEntry.getTarget());
        assertEquals("CRITICAL", restartEntry.getSeverity());
        assertTrue(restartEntry.getDetails().contains("Immediate restart initiated by harry"));
    }

    @Test
    void resolveCurrentUsernameUsesPendingSafeRestartInitiator() {
        RequestHolder.setPendingSafeRestartInitiator("harry");
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("SYSTEM", "secret"));

        assertEquals("harry", AuditRestartListener.resolveCurrentUsername(true));
        assertNull(RequestHolder.consumePendingSafeRestartInitiator());
    }
}
