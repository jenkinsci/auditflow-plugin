package io.jenkins.plugins.auditlogger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.junit.Test;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuditLogStorageRotationRegressionTest {

    private static final Gson GSON = new GsonBuilder()
            .registerTypeAdapter(AuditLogEntry.class, new AuditLogEntrySerializer())
            .disableHtmlEscaping()
            .create();

    @Test
    @SuppressWarnings("unchecked")
    public void loadEntriesFromDiskIncludesLegacyAndDailyRotatedFilesInTimestampOrder() throws Exception {
        Path tempDir = Files.createTempDirectory("auditflow-storage-order");
        AuditLogStorage storage = newStorage();

        try {
            Path logsDir = Files.createDirectories(tempDir.resolve("auditflow-logs"));

            writeJsonLine(logsDir.resolve("audit.20260507-022816.jsonl"), entry("alice", "LOGIN", 1_746_604_800_000L));
            writeJsonLine(logsDir.resolve("audit_2026-05-08_1.jsonl"), entry("bob", "JOB_CONFIG_UPDATED", 1_746_691_200_000L));
            writeJsonLine(logsDir.resolve("audit.jsonl"), entry("charlie", "BUILD_COMPLETED", 1_746_777_600_000L));

            Method loadEntries = AuditLogStorage.class.getDeclaredMethod(
                    "loadEntriesFromDisk", java.io.File.class, String.class, String.class, Long.class, Long.class);
            loadEntries.setAccessible(true);

            List<AuditLogEntry> entries = (List<AuditLogEntry>) loadEntries.invoke(
                    storage, logsDir.toFile(), null, null, null, null);

            assertEquals(3, entries.size());
            assertEquals("alice", entries.get(0).getUsername());
            assertEquals("bob", entries.get(1).getUsername());
            assertEquals("charlie", entries.get(2).getUsername());
            assertTrue(entries.get(0).getTimestamp() < entries.get(1).getTimestamp());
            assertTrue(entries.get(1).getTimestamp() < entries.get(2).getTimestamp());
        } finally {
            storage.shutdown();
        }
    }

    @Test
    public void rotateLogFileUsesDailyArchiveNameForFirstSegment() throws Exception {
        Path tempDir = Files.createTempDirectory("auditflow-day-rotation");
        AuditLogStorage storage = newStorage();

        try {
            Path logsDir = Files.createDirectories(tempDir.resolve("auditflow-logs"));
            LocalDate day = LocalDate.of(2026, 5, 8);

            writeJsonLine(logsDir.resolve("audit.jsonl"), entry("alice", "LOGIN", toEpochMillis(day, 10)));

            Method rotateLogFile = AuditLogStorage.class.getDeclaredMethod("rotateLogFile", java.io.File.class, LocalDate.class);
            rotateLogFile.setAccessible(true);
            rotateLogFile.invoke(storage, logsDir.resolve("audit.jsonl").toFile(), day);

            assertTrue(Files.exists(logsDir.resolve("audit_2026-05-08.jsonl")));
            assertFalse(Files.exists(logsDir.resolve("audit.jsonl")));
        } finally {
            storage.shutdown();
        }
    }

    @Test
    public void rotateLogFileUsesNumberedSuffixWhenDayAlreadyHasArchive() throws Exception {
        Path tempDir = Files.createTempDirectory("auditflow-size-rotation");
        AuditLogStorage storage = newStorage();

        try {
            Path logsDir = Files.createDirectories(tempDir.resolve("auditflow-logs"));
            LocalDate day = LocalDate.of(2026, 5, 9);

            writeJsonLine(logsDir.resolve("audit_2026-05-09.jsonl"), entry("archived", "LOGIN", toEpochMillis(day, 8)));
            writeJsonLine(logsDir.resolve("audit.jsonl"), entry("active", "BUILD_STARTED", toEpochMillis(day, 9)));

            Method rotateLogFile = AuditLogStorage.class.getDeclaredMethod("rotateLogFile", java.io.File.class, LocalDate.class);
            rotateLogFile.setAccessible(true);
            rotateLogFile.invoke(storage, logsDir.resolve("audit.jsonl").toFile(), day);

            assertTrue(Files.exists(logsDir.resolve("audit_2026-05-09_1.jsonl")));
            assertFalse(Files.exists(logsDir.resolve("audit.jsonl")));
        } finally {
            storage.shutdown();
        }
    }

    @Test
    public void pruneExpiredLogFilesDeletesArchivesOlderThanRetentionWindow() throws Exception {
        Path tempDir = Files.createTempDirectory("auditflow-retention");
        AuditLogStorage storage = newStorage();

        try {
            Path logsDir = Files.createDirectories(tempDir.resolve("auditflow-logs"));
            LocalDate today = LocalDate.now(ZoneOffset.UTC);
            LocalDate expiredDay = today.minusDays(8);
            LocalDate keptDay = today.minusDays(2);

            writeJsonLine(logsDir.resolve(legacyRotatedName(expiredDay, "010000")), entry("expired", "LOGIN", toEpochMillis(expiredDay, 1)));
            writeJsonLine(logsDir.resolve("audit_" + keptDay + ".jsonl"), entry("kept", "LOGIN", toEpochMillis(keptDay, 1)));

            Method pruneExpired = AuditLogStorage.class.getDeclaredMethod(
                    "pruneExpiredLogFiles", java.io.File.class, int.class);
            pruneExpired.setAccessible(true);
            pruneExpired.invoke(storage, logsDir.toFile(), 5);

            assertFalse(Files.exists(logsDir.resolve("audit_" + expiredDay + ".jsonl")));
            assertTrue(Files.exists(logsDir.resolve("audit_" + keptDay + ".jsonl")));
        } finally {
            storage.shutdown();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void scriptConsoleAccessFilterMatchesLegacyActionName() throws Exception {
        Path tempDir = Files.createTempDirectory("auditflow-script-access-filter");
        AuditLogStorage storage = newStorage();

        try {
            Path logsDir = Files.createDirectories(tempDir.resolve("auditflow-logs"));

            writeJsonLine(logsDir.resolve("audit.jsonl"), entry("alice", "SCRIPT_CONSOLE_ACCESSED", 1_746_691_200_000L));
            writeJsonLine(logsDir.resolve("audit.jsonl"), entry("alice", "SCRIPT_CONSOLE_ACCESS", 1_746_691_201_000L));

            Method loadEntries = AuditLogStorage.class.getDeclaredMethod(
                    "loadEntriesFromDisk", java.io.File.class, String.class, String.class, Long.class, Long.class);
            loadEntries.setAccessible(true);

            List<AuditLogEntry> entries = (List<AuditLogEntry>) loadEntries.invoke(
                    storage, logsDir.toFile(), null, "SCRIPT_CONSOLE_ACCESS", null, null);

            assertEquals(2, entries.size());
            assertEquals("SCRIPT_CONSOLE_ACCESSED", entries.get(0).getAction());
            assertEquals("SCRIPT_CONSOLE_ACCESS", entries.get(1).getAction());
        } finally {
            storage.shutdown();
        }
    }

    private static AuditLogStorage newStorage() throws Exception {
        Constructor<AuditLogStorage> constructor = AuditLogStorage.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        return constructor.newInstance();
    }

    private static AuditLogEntry entry(String user, String action, long timestamp) {
        return new AuditLogEntry(user, action, "jenkins", "rotation regression", timestamp);
    }

    private static long toEpochMillis(LocalDate date, int hourUtc) {
        return date.atTime(hourUtc, 0).toInstant(ZoneOffset.UTC).toEpochMilli();
    }

    private static void writeJsonLine(Path file, AuditLogEntry entry) throws IOException {
        Files.writeString(file,
                GSON.toJson(entry) + System.lineSeparator(),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
    }

    private static String legacyRotatedName(LocalDate date, String time) {
        return "audit." + date.format(DateTimeFormatter.BASIC_ISO_DATE) + "-" + time + ".jsonl";
    }
}