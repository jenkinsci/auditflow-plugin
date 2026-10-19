package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ComplianceReportGeneratorTest {

    @Test
    public void testSoxReport() {
        Date start = new Date(System.currentTimeMillis() - 10000);
        Date end = new Date(System.currentTimeMillis() + 10000);

        List<AuditLogEntry> entries = new ArrayList<>();
        AuditLogEntry login = new AuditLogEntry("alice", "LOGIN", "Jenkins", "ok", System.currentTimeMillis());
        entries.add(login);

        AuditLogEntry cfg = new AuditLogEntry("alice", "GLOBAL_CONFIG_UPDATED", "system", "updated", System.currentTimeMillis());
        entries.add(cfg);

        AuditLogEntry fail = new AuditLogEntry("bob", "FAILED_LOGIN", "Jenkins", "fail", System.currentTimeMillis());
        entries.add(fail);

        ComplianceReportGenerator.ComplianceReport report = ComplianceReportGenerator.generateSoxReport(entries, start, end);
        assertNotNull(report);
        assertEquals("SOX", report.reportType);
        assertNotNull(report.status);
        assertTrue(report.summary.containsKey("authenticationEvents"));
        assertTrue(report.summary.containsKey("configurationChanges"));

        String formatted = ComplianceReportGenerator.formatReport(report);
        assertTrue(formatted.contains("=== SOX COMPLIANCE REPORT ==="));
    }

    @Test
    public void testPciReport() {
        Date start = new Date(System.currentTimeMillis() - 10000);
        Date end = new Date(System.currentTimeMillis() + 10000);

        List<AuditLogEntry> entries = new ArrayList<>();
        AuditLogEntry cred = new AuditLogEntry("admin", "CREDENTIAL_CREATED", "cred1", "created", System.currentTimeMillis());
        entries.add(cred);

        ComplianceReportGenerator.ComplianceReport report = ComplianceReportGenerator.generatePciReport(entries, start, end);
        assertNotNull(report);
        assertEquals("PCI-DSS", report.reportType);
        assertTrue(report.summary.containsKey("credentialManagementEvents"));
    }

    @Test
    public void testGdprReport() {
        Date start = new Date(System.currentTimeMillis() - 10000);
        Date end = new Date(System.currentTimeMillis() + 10000);

        List<AuditLogEntry> entries = new ArrayList<>();
        AuditLogEntry mod = new AuditLogEntry("admin", "USER_CREATED", "user1", "created", System.currentTimeMillis());
        entries.add(mod);

        ComplianceReportGenerator.ComplianceReport report = ComplianceReportGenerator.generateGdprReport(entries, start, end);
        assertNotNull(report);
        assertEquals("GDPR", report.reportType);
        assertEquals("COMPLIANT", report.status);
    }
}
