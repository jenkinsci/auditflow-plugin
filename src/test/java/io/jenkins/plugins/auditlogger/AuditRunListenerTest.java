package io.jenkins.plugins.auditlogger;

import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestBuilder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
public class AuditRunListenerTest {

    @BeforeEach
    void setUp() throws Exception {
        RequestHolder.clear();
        SecurityContextHolder.clearContext();
        AuditLogStorage.clearInstance();
        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

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
        } catch (RuntimeException ignored) {}
        AuditLogStorage.clearInstance();
    }

    @Test
    void testBuildLifecycleAuditing(JenkinsRule j) throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("bob", "password", Collections.emptyList()));

        FreeStyleProject project = j.createFreeStyleProject("build-audit-job");
        FreeStyleBuild build = j.buildAndAssertSuccess(project);
        assertNotNull(build);

        List<AuditLogEntry> logs = AuditLogStorage.getInstance().getAllEntries();
        boolean hasBuildStarted = logs.stream().anyMatch(e -> e.getAction().contains("BUILD_STARTED") && e.getTarget().contains("build-audit-job"));
        assertTrue(hasBuildStarted, "BUILD_STARTED should be recorded");

        AuditLogEntry completedEntry = logs.stream()
                .filter(e -> "BUILD_COMPLETED".equals(e.getAction()) && e.getTarget().contains("build-audit-job"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("BUILD_COMPLETED should be recorded"));
        assertEquals("LOW", completedEntry.getSeverity(), "Successful completed builds should be green");

        HttpServletRequest req = (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> {
                    if ("getRemoteUser".equals(method.getName())) return "bob";
                    return null;
                });
        RequestHolder.set(req);
        try {
            build.delete();
            boolean hasBuildDeleted = false;
            for (int i = 0; i < 40; i++) {
                Thread.sleep(100);
                logs = AuditLogStorage.getInstance().getAllEntries();
                if (logs.stream().anyMatch(e -> e.getAction().contains("BUILD_DELETED") && e.getTarget().contains("build-audit-job"))) {
                    hasBuildDeleted = true;
                    break;
                }
            }
            assertTrue(hasBuildDeleted, "BUILD_DELETED should be recorded");
        } finally {
            RequestHolder.clear();
        }
    }

    @Test
    void testUnstableCompletedBuildUsesWarningSeverity(JenkinsRule j) throws Exception {
        FreeStyleProject project = j.createFreeStyleProject("unstable-build-audit-job");
        project.getBuildersList().add(new UnstableBuilder());
        j.buildAndAssertStatus(Result.UNSTABLE, project);

        AuditLogEntry completedEntry = AuditLogStorage.getInstance().getAllEntries().stream()
                .filter(e -> "BUILD_COMPLETED".equals(e.getAction())
                        && e.getTarget().contains("unstable-build-audit-job")
                        && e.getDetails().contains("UNSTABLE"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Unstable BUILD_COMPLETED should be recorded"));
        assertEquals("MEDIUM", completedEntry.getSeverity(), "Unstable completed builds should be yellow");
    }

    private static final class UnstableBuilder extends TestBuilder {
        @Override
        public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {
            build.setResult(Result.UNSTABLE);
            return true;
        }
    }
}
