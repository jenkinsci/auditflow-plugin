package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AuditLogIndexTest {

    private AuditLogIndex index;

    @BeforeEach
    public void setup() {
        index = new AuditLogIndex();
    }

    @Test
    public void testIndexAndQuery() {
        long now = System.currentTimeMillis();
        AuditLogEntry e1 = new AuditLogEntry("alice", "LOGIN", "Jenkins", "ok", now);
        e1.setSeverity("LOW");

        AuditLogEntry e2 = new AuditLogEntry("bob", "FAILED_LOGIN", "Jenkins", "fail", now + 1000);
        e2.setSeverity("HIGH");

        AuditLogEntry e3 = new AuditLogEntry("alice", "JOB_CREATED", "job1", "created", now + 2000);
        e3.setSeverity("INFO");

        index.index(e1);
        index.index(e2);
        index.index(e3);

        List<AuditLogEntry> aliceEntries = index.queryByUser("alice");
        assertEquals(2, aliceEntries.size());

        List<AuditLogEntry> loginEntries = index.queryByAction("LOGIN");
        assertEquals(1, loginEntries.size());

        List<AuditLogEntry> highEntries = index.queryBySeverity("HIGH");
        assertEquals(1, highEntries.size());
        assertEquals("bob", highEntries.get(0).getUsername());

        List<AuditLogEntry> timeEntries = index.queryByTime(now - 1000, now + 5000);
        assertEquals(3, timeEntries.size());

        Map<String, Integer> stats = index.getStatistics();
        assertEquals(2, stats.get("users"));
        assertEquals(3, stats.get("actions"));
    }

    @Test
    public void testCombinedQuery() {
        long now = System.currentTimeMillis();
        AuditLogEntry e = new AuditLogEntry("admin", "JOB_DELETED", "jobX", "deleted", now);
        e.setSeverity("HIGH");
        index.index(e);

        List<AuditLogEntry> res = index.query("admin", "JOB_DELETED", now - 1000, now + 1000, "HIGH");
        assertEquals(1, res.size());

        List<AuditLogEntry> mismatch = index.query("admin", "JOB_DELETED", now - 1000, now + 1000, "LOW");
        assertTrue(mismatch.isEmpty());
    }

    @Test
    public void testClear() {
        index.index(new AuditLogEntry("alice", "LOGIN", "Jenkins", "ok"));
        assertEquals(1, index.queryByUser("alice").size());

        index.clear();
        assertTrue(index.queryByUser("alice").isEmpty());
    }

    @Test
    public void testActionMatching() {
        assertTrue(AuditLogIndex.matchesAction("[CLI] JOB_DELETED", "JOB_DELETED"));
        assertTrue(AuditLogIndex.matchesAction("[CLI] JOB DELETED", "JOB_DELETED"));
        assertTrue(AuditLogIndex.matchesAction("JOB_DELETED", "JOB DELETED"));
        assertTrue(AuditLogIndex.matchesAction("LOGIN", "AUTH"));
        assertTrue(AuditLogIndex.matchesAction("FAILED_LOGIN", "AUTH"));
        assertTrue(AuditLogIndex.matchesAction("API_AUTH", "AUTH"));
        assertFalse(AuditLogIndex.matchesAction("JOB_CREATED", "AUTH"));
        assertTrue(AuditLogStorage.matchesActionFilter("[CLI] JOB DELETED", "JOB_DELETED"));
        assertTrue(AuditLogStorage.matchesActionFilter("LOGIN", "AUTH"));
    }

    @Test
    public void testQueryWithNullUsernameInEntries() throws Exception {
        AuditLogEntry e = new AuditLogEntry("placeholder", "JOB_DELETED", "jobX", "deleted");
        java.lang.reflect.Field userField = AuditLogEntry.class.getDeclaredField("username");
        userField.setAccessible(true);
        userField.set(e, null);

        index.index(e);

        List<AuditLogEntry> res = assertDoesNotThrow(() ->
                index.query("admin", "JOB_DELETED", null, null, null));
        assertTrue(res.isEmpty());
    }
}
