package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.PeriodicWork;
import jenkins.model.Jenkins;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Periodic log retention cleanup. Runs hourly.
 * Deletes rotated log files older than the configured retention period.
 * Does NOT delete the current active log file.
 */
@Extension
public class LogRotationService extends PeriodicWork {
    private static final Logger LOGGER = Logger.getLogger(LogRotationService.class.getName());

    @Override
    public long getRecurrencePeriod() {
        return 3_600_000; // 1 hour
    }

    @Override
    protected void doRun() {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null) return;

            int retentionDays = config.getLogRetentionDays();
            if (retentionDays <= 0) return; // 0 = keep forever

            deleteOldLogs(retentionDays);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in log rotation service", e);
        }
    }

    void deleteOldLogs(int retentionDays) {
        AuditLogStorage storage = AuditLogStorage.getInstance();
        if (storage != null) {
            storage.pruneExpiredLogFiles(retentionDays);
        }
    }
}
