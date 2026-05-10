package io.jenkins.plugins.auditlogger;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuditLoggerManagementLinkPaginationRegressionTest {

    @Test
    void filterAndPaginateKeepsNewestEntriesOnFirstServerPage() {
        List<AuditLogEntry> entries = Arrays.asList(
                entry("alice", "LOGIN", 1_700L),
                entry("SYSTEM", "PLUGIN_ENABLED", 2_000L),
                entry("bob", "BUILD_STARTED", 3_000L),
                entry("charlie", "JOB_CREATED", 4_000L));

        AuditLoggerManagementLink.AuditViewRequest request = new AuditLoggerManagementLink.AuditViewRequest(
                null,
                "all",
                null,
                null,
                null,
                "user-only",
                "timestampMs",
                false,
                1,
                2);

        List<AuditLogEntry> filtered = AuditLoggerManagementLink.filterAndSortEntries(entries, request, ZoneId.of("UTC"));
        AuditLoggerManagementLink.PageSlice page = AuditLoggerManagementLink.paginateEntries(filtered, request.page, request.pageSize);

        assertEquals(3, filtered.size());
        assertEquals(2, page.entries.size());
        assertEquals("charlie", page.entries.get(0).getUsername());
        assertEquals("bob", page.entries.get(1).getUsername());
    }

    @Test
    void toDisplayEntryUsesConfiguredDisplayTimezone() {
        AuditLogEntry entry = entry("alice", "LOGIN", 1_746_691_200_000L);
        ZoneId zone = ZoneId.of("Asia/Kolkata");

        Map<String, Object> display = AuditLoggerManagementLink.toDisplayEntry(entry, zone);

        assertEquals(entry.getFormattedTimestamp(), display.get("timestamp"));
        assertEquals(entry.getReadableTimestamp(zone), display.get("readable"));
    }

    @Test
    void defaultRangeUsesLastSevenDays() {
        LocalDate today = LocalDate.of(2026, 5, 10);

        assertEquals("7d", AuditLoggerManagementLink.computeDefaultDatePreset());
        assertEquals("2026-05-04", AuditLoggerManagementLink.computeDefaultDateFrom(today));
        assertEquals("2026-05-10", AuditLoggerManagementLink.computeDefaultDateTo(today));
        assertEquals("", AuditLoggerManagementLink.computeDefaultDateFrom(null));
        assertEquals("", AuditLoggerManagementLink.computeDefaultDateTo(null));
    }

    @Test
    void pageHeadingVersionOmitsPrivateBuildSuffix() {
        assertEquals("999999-SNAPSHOT", AuditLoggerManagementLink.sanitizePluginVersion("999999-SNAPSHOT (private-1ef53db0-harip)"));
        assertEquals("999999-SNAPSHOT", AuditLoggerManagementLink.sanitizePluginVersion("999999-SNAPSHOT"));
        assertEquals("dev", AuditLoggerManagementLink.sanitizePluginVersion(""));
    }

    private static AuditLogEntry entry(String user, String action, long timestamp) {
        return new AuditLogEntry(user, action, "jenkins", "management link regression", timestamp);
    }
}
