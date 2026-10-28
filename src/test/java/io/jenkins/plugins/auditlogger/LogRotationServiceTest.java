package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.io.File;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class LogRotationServiceTest {

    @Test
    void testLogRotationServiceDelegatesToStorageAndPreservesActiveFile(JenkinsRule j) throws Exception {
        AuditLogStorage storage = AuditLogStorage.getInstance();
        File logsDir = new File(j.jenkins.getRootDir(), "auditflow-logs");
        logsDir.mkdirs();

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate now = LocalDate.now(ZoneOffset.UTC);

        // Active file - must never be deleted
        File activeFile = new File(logsDir, "audit.jsonl");
        activeFile.createNewFile();

        // Expired rotated file (100 days old)
        File oldRotated = new File(logsDir, "audit_" + formatter.format(now.minusDays(100)) + ".jsonl");
        oldRotated.createNewFile();

        // Recent rotated file (10 days old)
        File recentRotated = new File(logsDir, "audit_" + formatter.format(now.minusDays(10)) + ".jsonl");
        recentRotated.createNewFile();

        LogRotationService service = new LogRotationService();
        service.deleteOldLogs(30);

        assertTrue(activeFile.exists(), "Active audit.jsonl must never be deleted");
        assertTrue(recentRotated.exists(), "Recent rotated file within 30-day retention must be retained");
        assertFalse(oldRotated.exists(), "Expired rotated file older than 30 days must be pruned");
    }
}

