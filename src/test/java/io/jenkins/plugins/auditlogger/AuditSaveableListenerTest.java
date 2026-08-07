package io.jenkins.plugins.auditlogger;

import hudson.model.FreeStyleProject;
import hudson.model.Saveable;
import hudson.model.User;
import hudson.slaves.DumbSlave;
import hudson.slaves.JNLPLauncher;
import hudson.slaves.RetentionStrategy;
import io.jenkins.plugins.thememanager.ThemeUserProperty;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class AuditSaveableListenerTest {

    private AuditSaveableListener listener;

    // Static inner classes designed so getClass().getName() matches isRuntimeBuildSaveable filters
    public static class WorkflowRunSaveable implements Saveable { @Override public void save() {} }
    public static class MatrixRunSaveable implements Saveable { @Override public void save() {} }
    public static class FingerprintSaveable implements Saveable { @Override public void save() {} }
    public static class FlowNodeSaveable implements Saveable { @Override public void save() {} }
    public static class PipelineTestSaveable implements Saveable { @Override public void save() {} }
    public static class ActionSaveable implements Saveable { @Override public void save() {} }

    @BeforeEach
    void setUp() throws Exception {
        listener = new AuditSaveableListener();
        RequestHolder.clear();
        SecurityContextHolder.clearContext();
        AuditLogStorage.clearInstance();
        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        // End/bypass startup grace period for precise test assertions
        Field startupTimeField = StartupPhaseManager.class.getDeclaredField("startupTime");
        startupTimeField.setAccessible(true);
        startupTimeField.set(null, 1L);
        StartupPhaseManager.resetRecentLogsForTests();
    }

    @AfterEach
    void tearDown() {
        RequestHolder.clear();
        SecurityContextHolder.clearContext();
        try {
            AuditLogStorage.getInstance().shutdown();
        } catch (RuntimeException ignored) {
            // Best-effort cleanup
        }
        AuditLogStorage.clearInstance();
        StartupPhaseManager.resetRecentLogsForTests();
    }

    @Test
    void testRuntimeBuildSaveableSuppression(JenkinsRule j) {
        RequestHolder.setAuthenticatedUser("admin");
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);

        int initialCount = AuditLogStorage.getInstance().getAllEntries().size();

        Saveable[] runtimeBuildSaveables = {
                new WorkflowRunSaveable(),
                new MatrixRunSaveable(),
                new FingerprintSaveable(),
                new FlowNodeSaveable(),
                new PipelineTestSaveable(),
                new ActionSaveable()
        };

        for (Saveable s : runtimeBuildSaveables) {
            listener.onChange(s, null);
        }

        assertEquals(initialCount, AuditLogStorage.getInstance().getAllEntries().size(),
                "Runtime build saveables must be suppressed from global audit logs");
    }

    @Test
    void testUserThemePreferenceSaveSuppression(JenkinsRule j) {
        RequestHolder.setAuthenticatedUser("admin");
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);

        int initialCount = AuditLogStorage.getInstance().getAllEntries().size();

        ThemeUserProperty themeSaveable = new ThemeUserProperty();
        listener.onChange(themeSaveable, null);

        assertEquals(initialCount, AuditLogStorage.getInstance().getAllEntries().size(),
                "User theme preference saves must be suppressed");
    }

    @Test
    void testNodeSaveSuppression(JenkinsRule j) throws Exception {
        RequestHolder.setAuthenticatedUser("admin");
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);

        DumbSlave node = new DumbSlave("saveable-node", "dummy", "/tmp", "1",
                hudson.model.Node.Mode.NORMAL, "", new JNLPLauncher(), RetentionStrategy.NOOP, Collections.emptyList());

        listener.onChange(node, null);

        List<AuditLogEntry> globalEntries = AuditLogStorage.getInstance().getAllEntries().stream()
                .filter(e -> "GLOBAL_CONFIG_UPDATED".equals(e.getAction()))
                .toList();

        assertTrue(globalEntries.isEmpty(), "Node saveables must be ignored by AuditSaveableListener");
    }

    @Test
    void testJobConfigUpdatedAudited(JenkinsRule j) throws Exception {
        RequestHolder.setAuthenticatedUser("admin");
        AuditLoggerConfiguration.get().setEnableJobConfigEvents(true);

        FreeStyleProject project = j.createFreeStyleProject("demo-audit-job");
        listener.onChange(project, null);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().getAllEntries().stream()
                .filter(e -> "JOB_CONFIG_UPDATED".equals(e.getAction()))
                .toList();

        assertEquals(1, entries.size());
        assertEquals("JOB_CONFIG_UPDATED", entries.get(0).getAction());
        assertEquals("demo-audit-job", entries.get(0).getTarget());
        assertEquals("admin", entries.get(0).getUsername());
    }

    @Test
    void testJobConfigUpdatedDisabled(JenkinsRule j) throws Exception {
        RequestHolder.setAuthenticatedUser("admin");
        AuditLoggerConfiguration.get().setEnableJobConfigEvents(false);

        FreeStyleProject project = j.createFreeStyleProject("disabled-audit-job");
        listener.onChange(project, null);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().getAllEntries().stream()
                .filter(e -> "JOB_CONFIG_UPDATED".equals(e.getAction()))
                .toList();

        assertTrue(entries.isEmpty(), "Job config events should be suppressed when feature toggle is false");
    }

    @Test
    void testUserConfigUpdatedAudited(JenkinsRule j) {
        RequestHolder.setAuthenticatedUser("admin");
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);

        User user = User.getById("test-user-profile", true);
        listener.onChange(user, null);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().getAllEntries().stream()
                .filter(e -> "USER_CONFIG_UPDATED".equals(e.getAction()))
                .toList();

        assertEquals(1, entries.size());
        assertEquals("USER_CONFIG_UPDATED", entries.get(0).getAction());
        assertEquals("test-user-profile", entries.get(0).getTarget());
        assertEquals("admin", entries.get(0).getUsername());
    }

    @Test
    void testGlobalConfigUpdatedAudited(JenkinsRule j) {
        RequestHolder.setAuthenticatedUser("admin");
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);

        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        listener.onChange(config, null);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().getAllEntries().stream()
                .filter(e -> "GLOBAL_CONFIG_UPDATED".equals(e.getAction()))
                .toList();

        assertEquals(1, entries.size());
        assertEquals("GLOBAL_CONFIG_UPDATED", entries.get(0).getAction());
        assertEquals("AuditLoggerConfiguration", entries.get(0).getTarget());
        assertEquals("admin", entries.get(0).getUsername());
        assertEquals("MEDIUM", entries.get(0).getSeverity());
    }

    @Test
    void testGlobalConfigUpdatedDisabled(JenkinsRule j) {
        RequestHolder.setAuthenticatedUser("admin");
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(false);

        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        listener.onChange(config, null);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().getAllEntries().stream()
                .filter(e -> "GLOBAL_CONFIG_UPDATED".equals(e.getAction()))
                .toList();

        assertTrue(entries.isEmpty(), "Global system config events should be suppressed when feature toggle is false");
    }

    @Test
    void testNonRealUserSuppressed(JenkinsRule j) {
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);
        int initialCount = AuditLogStorage.getInstance().getAllEntries().size();
        String[] nonRealUsers = {"SYSTEM", "anonymous", "anonymousUser"};

        for (String user : nonRealUsers) {
            RequestHolder.clear();
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(user, "credentials"));

            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            listener.onChange(config, null);
        }

        assertEquals(initialCount, AuditLogStorage.getInstance().getAllEntries().size(),
                "Non-real user background saves must be suppressed");
    }

    @Test
    void testDeduplication(JenkinsRule j) {
        RequestHolder.setAuthenticatedUser("admin");
        AuditLoggerConfiguration.get().setEnableSystemConfigEvents(true);

        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        listener.onChange(config, null);
        listener.onChange(config, null);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().getAllEntries().stream()
                .filter(e -> "GLOBAL_CONFIG_UPDATED".equals(e.getAction()))
                .toList();

        assertEquals(1, entries.size(), "Rapid duplicate save calls must be deduplicated");
    }

    @Test
    void testStaticHelpersWithNullAndVariousInputs() {
        assertDoesNotThrow(() -> listener.onChange(null, null));

        Method[] methods = AuditSaveableListener.class.getDeclaredMethods();
        for (Method method : methods) {
            if ("isRuntimeBuildSaveable".equals(method.getName())) {
                method.setAccessible(true);
                assertDoesNotThrow(() -> assertFalse((Boolean) method.invoke(null, (Object) null)));
                assertDoesNotThrow(() -> assertTrue((Boolean) method.invoke(null, new WorkflowRunSaveable())));
            }
            if ("isUserThemePreferenceSave".equals(method.getName())) {
                method.setAccessible(true);
                assertDoesNotThrow(() -> assertFalse((Boolean) method.invoke(null, (Object) null)));
                assertDoesNotThrow(() -> assertTrue((Boolean) method.invoke(null, new ThemeUserProperty())));
            }
            if ("isCredentialStore".equals(method.getName())) {
                method.setAccessible(true);
                assertDoesNotThrow(() -> assertFalse((Boolean) method.invoke(null, (Object) null)));
            }
        }
    }
}
