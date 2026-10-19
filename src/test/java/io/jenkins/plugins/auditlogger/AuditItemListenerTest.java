package io.jenkins.plugins.auditlogger;

import hudson.model.FreeStyleProject;
import hudson.model.TopLevelItem;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
public class AuditItemListenerTest {

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
    void testItemLifecycleAuditing(JenkinsRule j) throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("alice", "password", Collections.emptyList()));

        FreeStyleProject project = j.createFreeStyleProject("audit-test-job");
        assertNotNull(project);

        List<AuditLogEntry> logs = AuditLogStorage.getInstance().getAllEntries();
        boolean hasCreated = logs.stream().anyMatch(e -> e.getAction().contains("JOB_CREATED") && e.getTarget().contains("audit-test-job"));
        assertTrue(hasCreated, "JOB_CREATED audit entry should be recorded");

        project.renameTo("audit-test-job-renamed");
        logs = AuditLogStorage.getInstance().getAllEntries();
        boolean hasRenamed = logs.stream().anyMatch(e -> e.getAction().contains("JOB_RENAMED") && e.getTarget().contains("audit-test-job-renamed"));
        assertTrue(hasRenamed, "JOB_RENAMED audit entry should be recorded");

        j.jenkins.copy((TopLevelItem) project, "audit-test-job-copy");
        logs = AuditLogStorage.getInstance().getAllEntries();
        boolean hasCopied = logs.stream().anyMatch(e -> e.getAction().contains("JOB_COPIED") && e.getTarget().contains("audit-test-job-copy"));
        assertTrue(hasCopied, "JOB_COPIED audit entry should be recorded");

        project.delete();
        logs = AuditLogStorage.getInstance().getAllEntries();
        boolean hasDeleted = logs.stream().anyMatch(e -> e.getAction().contains("JOB_DELETED") && e.getTarget().contains("audit-test-job-renamed"));
        assertTrue(hasDeleted, "JOB_DELETED audit entry should be recorded");
    }
}
