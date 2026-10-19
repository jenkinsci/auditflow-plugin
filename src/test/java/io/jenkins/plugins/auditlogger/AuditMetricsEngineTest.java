package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AuditMetricsEngineTest {

    private AuditMetricsEngine engine;

    @BeforeEach
    public void setup() {
        engine = new AuditMetricsEngine();
    }

    @Test
    public void testRecordAndDashboardMetrics() {
        AuditLogEntry e1 = new AuditLogEntry("alice", "LOGIN", "Jenkins", "User logged in");
        e1.setSeverity("LOW");
        e1.setSourceIp("192.168.1.10");

        AuditLogEntry e2 = new AuditLogEntry("alice", "JOB_CREATED", "my-job", "Job created");
        e2.setSeverity("INFO");
        e2.setSourceIp("192.168.1.10");

        AuditLogEntry e3 = new AuditLogEntry("bob", "FAILED_LOGIN", "Jenkins", "Bad credentials");
        e3.setSeverity("HIGH");
        e3.setSourceIp("10.0.0.5");

        engine.record(e1);
        engine.record(e2);
        engine.record(e3);

        Map<String, Object> metrics = engine.getDashboardMetrics();
        assertNotNull(metrics);
        assertEquals(3L, metrics.get("totalEvents"));
        assertEquals(3, metrics.get("uniqueActions"));
        assertEquals(2, metrics.get("uniqueUsers"));

        List<Map<String, Object>> topActions = engine.getTopActions(5);
        assertFalse(topActions.isEmpty());

        List<Map<String, Object>> topUsers = engine.getTopUsers(5);
        assertEquals(2, topUsers.size());
    }

    @Test
    public void testSeverityDistribution() {
        AuditLogEntry e1 = new AuditLogEntry("alice", "LOGIN", "Jenkins", "ok");
        e1.setSeverity("CRITICAL");
        AuditLogEntry e2 = new AuditLogEntry("alice", "CONFIG", "system", "ok");
        e2.setSeverity("HIGH");

        engine.record(e1);
        engine.record(e2);

        Map<String, Object> dist = engine.getSeverityDistribution();
        assertEquals(1, dist.get("CRITICAL"));
        assertEquals(1, dist.get("HIGH"));
        assertEquals(0, dist.get("LOW"));
    }

    @Test
    public void testSuspiciousUsers() {
        // bob has only failed logins -> failure rate 100% (> 30%)
        AuditLogEntry fail = new AuditLogEntry("bad_actor", "FAILED_LOGIN", "Jenkins", "fail");
        engine.record(fail);

        List<Map<String, Object>> suspicious = engine.getSuspiciousUsers(5);
        assertEquals(1, suspicious.size());
        assertEquals("bad_actor", suspicious.get(0).get("username"));
        assertEquals("100.0%", suspicious.get(0).get("failureRate"));
    }

    @Test
    public void testComplianceMetrics() {
        AuditLogEntry login = new AuditLogEntry("alice", "LOGIN", "Jenkins", "in");
        AuditLogEntry cfg = new AuditLogEntry("alice", "GLOBAL_CONFIG_UPDATED", "system", "mod");

        engine.record(login);
        engine.record(cfg);

        Map<String, Object> comp = engine.getComplianceMetrics();
        assertNotNull(comp);
        assertEquals(1L, comp.get("authenticationEvents"));
        assertEquals(1L, comp.get("configurationChanges"));
    }

    @Test
    public void testNullEntryHandling() {
        engine.record(null); // Should not throw
        assertEquals(0L, engine.getDashboardMetrics().get("totalEvents"));
    }
}
