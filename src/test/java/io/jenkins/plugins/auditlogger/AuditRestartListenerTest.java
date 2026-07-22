package io.jenkins.plugins.auditlogger;

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
class AuditRestartListenerTest {

    @AfterEach
    void cleanup() {
        RequestHolder.clear();
        RequestHolder.clearPendingRestart();
        AuditRestartListener.resetForTests();
        SecurityContextHolder.clearContext();
        try {
            AuditLogStorage.getInstance().shutdown();
        } catch (RuntimeException ignored) {
            // Best-effort cleanup for isolated test storage.
        }
        AuditLogStorage.clearInstance();
    }

    @Test
    void onRestartLogsPendingPluginRestartWithRealUser(JenkinsRule j) {
        RequestHolder.rememberPendingRestart("harry", true, false);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("SYSTEM", "secret"));

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        new AuditRestartListener().onRestart();

        AuditLogEntry restartEntry = storage.getAllEntries().stream()
                .filter(entry -> "SYSTEM_RESTART".equals(entry.getAction()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing SYSTEM_RESTART audit entry"));

        assertEquals("harry", restartEntry.getUsername());
        assertEquals("CRITICAL", restartEntry.getSeverity());
        assertTrue(restartEntry.getDetails().contains("Safe restart initiated by harry"));
    }

    @Test
    void pluginStopLogsPendingPluginRestartWhenRestartListenerWasSkipped(JenkinsRule j) {
        RequestHolder.rememberPendingRestart("harry", true, false);

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        AuditRestartListener.logPendingRestartOnPluginStop();

        AuditLogEntry restartEntry = storage.getAllEntries().stream()
                .filter(entry -> "SYSTEM_RESTART".equals(entry.getAction()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing SYSTEM_RESTART audit entry"));

        assertEquals("harry", restartEntry.getUsername());
        assertTrue(restartEntry.getDetails().contains("Safe restart initiated by harry"));
    }

    @Test
    void onRestartSkipsWhenRequestPathAlreadyLoggedRestart(JenkinsRule j) {
        RequestHolder.rememberPendingRestart("harry", true, true);

        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        new AuditRestartListener().onRestart();

        List<AuditLogEntry> restartEntries = storage.getAllEntries().stream()
                .filter(entry -> "SYSTEM_RESTART".equals(entry.getAction()))
                .toList();

        assertEquals(0, restartEntries.size());
    }
}
