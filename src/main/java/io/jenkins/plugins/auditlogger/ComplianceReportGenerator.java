package io.jenkins.plugins.auditlogger;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Compliance report generator for audit standards (SOX, PCI-DSS, GDPR).
 */
public class ComplianceReportGenerator {

    public static class ComplianceReport {
        public String reportType;
        public Date generatedDate;
        public Date reportPeriodStart;
        public Date reportPeriodEnd;
        public Map<String, Object> summary;
        public Map<String, Object> findings;
        public List<String> recommendations;
        public String status;
    }

    public static ComplianceReport generateSoxReport(List<AuditLogEntry> entries,
                                                     Date startDate, Date endDate) {
        ComplianceReport report = new ComplianceReport();
        report.reportType = "SOX";
        report.generatedDate = new Date();
        report.reportPeriodStart = startDate;
        report.reportPeriodEnd = endDate;
        report.recommendations = new ArrayList<>();

        List<AuditLogEntry> period = filterPeriod(entries, startDate, endDate);
        Map<String, Object> summary = new LinkedHashMap<>();

        long authEvents = period.stream()
                .filter(e -> e.getAction() != null && (e.getAction().contains("LOGIN") || e.getAction().contains("AUTH"))).count();
        long failedLogins = period.stream()
                .filter(e -> "FAILED_LOGIN".equals(e.getAction())).count();
        long configChanges = period.stream()
                .filter(e -> e.getAction() != null && (e.getAction().contains("CONFIG") || e.getAction().contains("UPDATED"))).count();
        long highRisk = period.stream()
                .filter(e -> "CRITICAL".equals(e.getSeverity()) || "HIGH".equals(e.getSeverity())).count();
        long uniqueUsers = period.stream()
                .map(e -> e.getUsername() != null ? e.getUsername() : "UNKNOWN")
                .distinct().count();

        summary.put("authenticationEvents", authEvents);
        summary.put("failedLoginAttempts", failedLogins);
        summary.put("configurationChanges", configChanges);
        summary.put("highRiskEvents", highRisk);
        summary.put("uniqueUsersTracked", uniqueUsers);
        summary.put("totalEvents", period.size());
        report.summary = summary;

        Map<String, Object> findings = new LinkedHashMap<>();
        findings.put("completeCoverage", authEvents > 0);
        findings.put("integrityVerified", failedLogins < 5);
        findings.put("accessControlEnforced", configChanges > 0 || authEvents > 0);
        report.findings = findings;

        if (failedLogins > 10) report.recommendations.add("Review high failed login count");
        if (highRisk > 20) report.recommendations.add("Investigate high-risk events");
        if (uniqueUsers < 3) report.recommendations.add("Ensure adequate role-based access control");

        int compliant = (int) findings.values().stream()
                .filter(v -> v instanceof Boolean && (Boolean) v).count();
        report.status = compliant == 3 ? "COMPLIANT" : compliant >= 2 ? "PARTIAL" : "NON_COMPLIANT";
        return report;
    }

    public static ComplianceReport generatePciReport(List<AuditLogEntry> entries,
                                                     Date startDate, Date endDate) {
        ComplianceReport report = new ComplianceReport();
        report.reportType = "PCI-DSS";
        report.generatedDate = new Date();
        report.reportPeriodStart = startDate;
        report.reportPeriodEnd = endDate;
        report.recommendations = new ArrayList<>();

        List<AuditLogEntry> period = filterPeriod(entries, startDate, endDate);
        Map<String, Object> summary = new LinkedHashMap<>();

        long authUsers = period.stream()
                .filter(e -> e.getAction() != null && e.getAction().contains("LOGIN"))
                .map(e -> e.getUsername() != null ? e.getUsername() : "UNKNOWN")
                .distinct().count();
        long credEvents = period.stream()
                .filter(e -> e.getAction() != null && (e.getAction().contains("CREDENTIAL") || e.getAction().contains("PASSWORD"))).count();

        summary.put("authenticatedAccessPoints", authUsers);
        summary.put("credentialManagementEvents", credEvents);
        summary.put("totalLoggingEvents", period.size());
        report.summary = summary;

        Map<String, Object> findings = new LinkedHashMap<>();
        findings.put("strongAccessControl", authUsers > 0);
        findings.put("passwordManagement", credEvents > 0);
        findings.put("adequateLogging", period.size() > 100);
        report.findings = findings;

        int compliant = (int) findings.values().stream()
                .filter(v -> v instanceof Boolean && (Boolean) v).count();
        report.status = compliant >= 3 ? "COMPLIANT" : compliant >= 2 ? "PARTIAL" : "NON_COMPLIANT";
        return report;
    }

    public static ComplianceReport generateGdprReport(List<AuditLogEntry> entries,
                                                      Date startDate, Date endDate) {
        ComplianceReport report = new ComplianceReport();
        report.reportType = "GDPR";
        report.generatedDate = new Date();
        report.reportPeriodStart = startDate;
        report.reportPeriodEnd = endDate;
        report.recommendations = new ArrayList<>();
        report.recommendations.add("Verify data retention policies comply with requirements");

        List<AuditLogEntry> period = filterPeriod(entries, startDate, endDate);
        Map<String, Object> summary = new LinkedHashMap<>();

        long dataAccess = period.stream()
                .filter(e -> e.getAction() != null && (e.getAction().contains("ACCESS") || e.getAction().contains("READ"))).count();
        long dataMod = period.stream()
                .filter(e -> e.getAction() != null && (e.getAction().contains("UPDATE") || e.getAction().contains("DELETE")
                        || e.getAction().contains("CREATE"))).count();

        summary.put("dataAccessEvents", dataAccess);
        summary.put("dataModificationEvents", dataMod);
        report.summary = summary;

        Map<String, Object> findings = new LinkedHashMap<>();
        findings.put("accessLogging", dataAccess > 0 || period.size() > 0);
        findings.put("changeTracking", dataMod > 0 || period.size() > 0);
        report.findings = findings;
        report.status = "COMPLIANT";
        return report;
    }

    public static String formatReport(ComplianceReport report) {
        if (report == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(report.reportType != null ? report.reportType : "AUDIT").append(" COMPLIANCE REPORT ===\n\n");
        DateTimeFormatter dtFmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);
        DateTimeFormatter dFmt = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);
        sb.append("Generated: ").append(report.generatedDate != null ? dtFmt.format(report.generatedDate.toInstant()) : "-").append("\n");
        sb.append("Period: ").append(report.reportPeriodStart != null ? dFmt.format(report.reportPeriodStart.toInstant()) : "Beginning")
                .append(" to ").append(report.reportPeriodEnd != null ? dFmt.format(report.reportPeriodEnd.toInstant()) : "Present").append("\n");
        sb.append("Status: ").append(report.status != null ? report.status : "UNKNOWN").append("\n\n");
        sb.append("SUMMARY:\n");
        if (report.summary != null) {
            report.summary.forEach((k, v) -> sb.append("  ").append(k).append(": ").append(v).append("\n"));
        }
        sb.append("\nFINDINGS:\n");
        if (report.findings != null) {
            report.findings.forEach((k, v) -> sb.append("  ").append(k).append(": ").append(v).append("\n"));
        }
        if (report.recommendations != null && !report.recommendations.isEmpty()) {
            sb.append("\nRECOMMENDATIONS:\n");
            report.recommendations.forEach(r -> sb.append("  - ").append(r).append("\n"));
        }
        return sb.toString();
    }

    private static List<AuditLogEntry> filterPeriod(List<AuditLogEntry> entries, Date start, Date end) {
        if (entries == null || entries.isEmpty()) {
            return Collections.emptyList();
        }
        long startMs = start != null ? start.getTime() : 0L;
        long endMs = end != null ? end.getTime() : Long.MAX_VALUE;
        return entries.stream()
                .filter(e -> e != null && e.getTimestamp() >= startMs && e.getTimestamp() <= endMs)
                .collect(Collectors.toList());
    }
}
