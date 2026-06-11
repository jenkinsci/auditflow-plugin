package io.jenkins.plugins.auditlogger;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import jenkins.model.Jenkins;

/**
 * Production-grade audit log storage.
 *
 * Design for heavy load:
 * - Lock-free ConcurrentLinkedQueue for incoming events (zero blocking on callers)
 * - Single daemon writer thread drains queue and writes batches
 * - Persistent BufferedWriter (no open/close per entry)
 * - Bounded in-memory ring buffer (ArrayDeque + ReadWriteLock) for UI/API queries
 * - Automatic file rotation on size threshold
 * - Proper shutdown with flush guarantee
 * - Data masking integrated before persistence
 */
public class AuditLogStorage {
    private static final Logger LOGGER = Logger.getLogger(AuditLogStorage.class.getName());
    private static final String AUDIT_LOGS_DIR = "auditflow-logs";
    private static final String LOG_FILE_NAME = "audit.jsonl";
    private static final String LEGACY_LOG_FILE_NAME = "audit.log";
    private static final String ROTATED_LOG_PREFIX = "audit_";
    private static final String LOG_FILE_EXTENSION = ".jsonl";
    private static final int MAX_ENTRIES_IN_MEMORY = 10_000;
    private static final int DEFAULT_BATCH_SIZE = 100;
    private static final long DEFAULT_FLUSH_INTERVAL_MS = 5_000;
    private static final int NEWLINE_BYTES = System.lineSeparator().getBytes(StandardCharsets.UTF_8).length;
    private static final DateTimeFormatter ROTATED_LOG_DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        private static final DateTimeFormatter LEGACY_ROTATED_LOG_DATE_FORMAT = DateTimeFormatter.BASIC_ISO_DATE;
    private static final Pattern ROTATED_LOG_PATTERN =
            Pattern.compile("^audit_(\\d{4}-\\d{2}-\\d{2})(?:_(\\d+))?\\.jsonl$");
        private static final Pattern LEGACY_ROTATED_LOG_PATTERN =
            Pattern.compile("^audit\\.(\\d{8})-(\\d{6})\\.jsonl$");

    // Singleton — one instance shared across all callers
    private static volatile AuditLogStorage instance;

    // Anomaly detection — wired into every event
    // not final so tests can inject a mock detector via reflection
    private AnomalyDetector anomalyDetector = new AnomalyDetector();

    // Bounded in-memory buffer for queries (UI, API, export)
    private final ArrayDeque<AuditLogEntry> memoryBuffer = new ArrayDeque<>(MAX_ENTRIES_IN_MEMORY + 64);
    private final ReentrantReadWriteLock bufferLock = new ReentrantReadWriteLock();

    // Lock-free write queue — callers never block
    private final ConcurrentLinkedQueue<AuditLogEntry> writeQueue = new ConcurrentLinkedQueue<>();
    private final AtomicInteger writeQueueSize = new AtomicInteger(0);

    // Persistent writer — opened once, flushed in batches
    private volatile BufferedWriter currentWriter;
    private volatile File currentLogFile;
    private volatile LocalDate currentLogDate;
    private volatile long currentLogSizeBytes;
    private final Object writerLock = new Object();

    // Async writer thread
    private final ScheduledExecutorService writerScheduler;
    private volatile boolean shuttingDown = false;

    private final Gson gson = new GsonBuilder()
            .registerTypeAdapter(AuditLogEntry.class, new AuditLogEntrySerializer())
            .disableHtmlEscaping()
            .create();

    private AuditLogStorage() {
        writerScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "Audit-Log-Writer");
            t.setDaemon(true);
            return t;
        });
    }

    public static AuditLogStorage getInstance() {
        AuditLogStorage local = instance;
        if (local == null) {
            synchronized (AuditLogStorage.class) {
                local = instance;
                if (local == null) {
                    instance = local = new AuditLogStorage();
                }
            }
        }
        return local;
    }

    /**
     * Initialize storage: ensure dirs, load recent logs, start writer thread.
     * Called once during plugin startup.
     */
    public void initialize() {
        ensureAuditLogsDirectoryExists();
        pruneExpiredLogFiles(getConfigurationSafely());
        loadRecentLogs();

        AuditLoggerConfiguration config = getConfigurationSafely();
        long flushMs = config != null ? config.getBatchFlushIntervalSeconds() * 1000L : DEFAULT_FLUSH_INTERVAL_MS;

        writerScheduler.scheduleWithFixedDelay(this::drainWriteQueue, flushMs, flushMs, TimeUnit.MILLISECONDS);
        LOGGER.info("Audit log storage initialized (dir=" + getAuditLogsDir().getAbsolutePath() + ")");
    }

    /**
     * Record an audit event. Non-blocking — entry is queued for async disk write.
     * Returns immediately; typical latency &lt; 1 microsecond.
     */
    public void addEntry(AuditLogEntry entry) {
        if (entry == null || shuttingDown) return;

        AuditLoggerConfiguration config = getConfigurationSafely();

        // Apply data masking before storing
        try {
            if (config != null && config.isMaskTokens()) {
                DataMasker.maskEntry(entry);
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Data masking failed, storing unmasked", e);
        }

        // Add to in-memory buffer (bounded)
        bufferLock.writeLock().lock();
        try {
            memoryBuffer.addLast(entry);
            while (memoryBuffer.size() > MAX_ENTRIES_IN_MEMORY) {
                memoryBuffer.removeFirst();
            }
        } finally {
            bufferLock.writeLock().unlock();
        }

        // Run anomaly detection after masking and buffering so alert text matches stored data.
        try {
            anomalyDetector.analyze(entry, config);
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Anomaly detection failed for entry", e);
        }

        // Queue for async disk write (lock-free)
        writeQueue.offer(entry);
        int queueLen = writeQueueSize.incrementAndGet();

        // If queue is large, trigger immediate drain (O(1) check)
        if (queueLen > getBatchSize() * 2) {
            writerScheduler.execute(this::drainWriteQueue);
        }
    }

    /**
     * Get all entries in memory (most recent MAX_ENTRIES_IN_MEMORY).
     * Returns a defensive copy.
     */
    public List<AuditLogEntry> getAllEntries() {
        drainWriteQueue();
        synchronized (writerLock) {
            pruneExpiredLogFiles(getConfigurationSafely());
            return loadEntriesFromDisk(null, null, null, null);
        }
    }

    /** Fast existence check used by the UI to avoid loading every entry during page render. */
    public boolean hasEntries() {
        drainWriteQueue();
        bufferLock.readLock().lock();
        try {
            if (!memoryBuffer.isEmpty()) {
                return true;
            }
        } finally {
            bufferLock.readLock().unlock();
        }

        synchronized (writerLock) {
            for (File file : listAuditLogFiles()) {
                if (file.exists() && file.length() > 0L) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Get the anomaly detector instance for querying alerts. */
    public AnomalyDetector getAnomalyDetector() {
        return anomalyDetector;
    }

    /**
     * Filter entries by criteria. Returns a defensive copy.
     */
    public List<AuditLogEntry> filterEntries(String username, String action, Long startTime, Long endTime) {
        drainWriteQueue();
        synchronized (writerLock) {
            pruneExpiredLogFiles(getConfigurationSafely());
            return loadEntriesFromDisk(username, action, startTime, endTime);
        }
    }

    /**
     * Drain write queue and flush entries to disk in a batch.
     * Called periodically by the scheduler and on-demand when queue is large.
     */
    private void drainWriteQueue() {
        // Safety net: write expired pending auth entries that were never enriched.
        // This prevents data loss when the user's next request doesn't reach AuditRequestCapture.
        List<AuditLogEntry> expired = RequestHolder.drainExpiredEntries();
        for (AuditLogEntry e : expired) {
            writeQueue.offer(e);
            writeQueueSize.incrementAndGet();
            // Also add to in-memory buffer
            bufferLock.writeLock().lock();
            try {
                memoryBuffer.addLast(e);
                while (memoryBuffer.size() > MAX_ENTRIES_IN_MEMORY) {
                    memoryBuffer.removeFirst();
                }
            } finally {
                bufferLock.writeLock().unlock();
            }
        }

        List<AuditLogEntry> batch = new ArrayList<>();
        AuditLogEntry entry;
        int maxDrain = getBatchSize() * 4; // prevent starvation if queue fills faster
        int drained = 0;
        while ((entry = writeQueue.poll()) != null && drained < maxDrain) {
            batch.add(entry);
            drained++;
        }
        writeQueueSize.addAndGet(-drained);
        if (batch.isEmpty()) return;

        synchronized (writerLock) {
            try {
                // Detect external file truncation/deletion and reopen writer
                if (currentWriter != null && currentLogFile != null) {
                    if (!currentLogFile.exists() || currentLogFile.length() == 0) {
                        closeWriter();
                        currentLogDate = null;
                        currentLogSizeBytes = 0L;
                    } else {
                        currentLogSizeBytes = currentLogFile.length();
                        if (currentLogDate == null) {
                            currentLogDate = resolveLogFileDate(currentLogFile);
                        }
                    }
                }

                AuditLoggerConfiguration config = getConfigurationSafely();
                long maxSize = config != null ? config.getMaxLogFileSizeBytes() : 50L * 1024 * 1024;
                boolean rotationEnabled = config == null || config.isEnableLogRotation();
                pruneExpiredLogFiles(config);

                for (AuditLogEntry e : batch) {
                    LocalDate entryDate = toLogDate(e.getTimestamp());
                    ensureWriterOpen(entryDate);

                    if (rotationEnabled) {
                        rotateForNewDay(entryDate);
                    }

                    String json = gson.toJson(e);
                    currentWriter.write(json);
                    currentWriter.newLine();

                    currentLogSizeBytes += estimateSerializedSize(json);

                    if (rotationEnabled && currentLogSizeBytes > maxSize) {
                        currentWriter.flush();
                        closeWriter();
                        rotateLogFile(currentLogFile, currentLogDate != null ? currentLogDate : entryDate);
                        ensureWriterOpen(entryDate);
                    }
                }

                currentWriter.flush();
                if (currentLogFile != null && currentLogFile.exists()) {
                    currentLogSizeBytes = currentLogFile.length();
                }
            } catch (IOException ex) {
                LOGGER.log(Level.SEVERE, "Failed to write " + batch.size() + " audit entries", ex);
                closeWriter();
                currentLogDate = null;
                currentLogSizeBytes = 0L;
                // Re-queue entries for retry (up to a limit to prevent infinite loop)
                if (writeQueueSize.get() < MAX_ENTRIES_IN_MEMORY) {
                    batch.forEach(e -> {
                        writeQueue.offer(e);
                        writeQueueSize.incrementAndGet();
                    });
                } else {
                    LOGGER.severe("AUDIT DATA LOSS: Write queue full (" + writeQueueSize.get()
                            + " entries). " + batch.size() + " entries DROPPED. "
                            + "Check disk space and I/O health immediately.");
                }
            }
        }
    }

    private void ensureWriterOpen(LocalDate preferredLogDate) throws IOException {
        if (currentWriter == null) {
            ensureAuditLogsDirectoryExists();
            currentLogFile = getCurrentLogFile();
            if (currentLogFile.exists() && currentLogFile.length() > 0) {
                currentLogSizeBytes = currentLogFile.length();
                currentLogDate = resolveLogFileDate(currentLogFile);
            } else {
                currentLogSizeBytes = currentLogFile.exists() ? currentLogFile.length() : 0L;
                currentLogDate = preferredLogDate != null ? preferredLogDate : currentUtcDate();
            }
            FileOutputStream fos = new FileOutputStream(currentLogFile, true);
            try {
                currentWriter = new BufferedWriter(
                        new OutputStreamWriter(fos, StandardCharsets.UTF_8),
                        32 * 1024); // 32KB write buffer
            } catch (RuntimeException e) {
                try {
                    fos.close();
                } catch (IOException closeError) {
                    e.addSuppressed(closeError);
                }
                throw e;
            }
        }
    }

    private void closeWriter() {
        if (currentWriter != null) {
            try {
                currentWriter.flush();
                currentWriter.close();
            } catch (IOException ignored) {
            }
            currentWriter = null;
        }
    }

    private void rotateForNewDay(LocalDate entryDate) throws IOException {
        if (currentLogFile == null || currentLogDate == null) {
            return;
        }
        if (!entryDate.isAfter(currentLogDate)) {
            return;
        }
        if (currentLogFile.exists() && currentLogSizeBytes > 0L) {
            closeWriter();
            rotateLogFile(currentLogFile, currentLogDate);
        }
        ensureWriterOpen(entryDate);
    }

    private void rotateLogFile(File logFile, LocalDate logDate) {
        if (logFile == null || !logFile.exists() || logFile.length() == 0L) {
            currentLogDate = null;
            currentLogSizeBytes = 0L;
            return;
        }
        try {
            File rotated = nextRotatedLogFile(logFile.getParentFile(), logDate != null ? logDate : currentUtcDate());
            try {
                Files.move(logFile.toPath(), rotated.toPath(), StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(logFile.toPath(), rotated.toPath());
            }
            LOGGER.info("Rotated audit log to: " + rotated.getName());
            currentLogDate = null;
            currentLogSizeBytes = 0L;
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to rotate log file", e);
        }
    }

    private File nextRotatedLogFile(File directory, LocalDate logDate) {
        String baseName = ROTATED_LOG_PREFIX + ROTATED_LOG_DATE_FORMAT.format(logDate);
        File candidate = new File(directory, baseName + LOG_FILE_EXTENSION);
        int suffix = 1;
        while (candidate.exists()) {
            candidate = new File(directory, baseName + "_" + suffix + LOG_FILE_EXTENSION);
            suffix++;
        }
        return candidate;
    }

    /**
     * Flush all pending writes and shut down the writer thread.
     * Called on plugin stop.
     */
    public void shutdown() {
        shuttingDown = true;
        drainWriteQueue(); // flush remaining
        writerScheduler.shutdown();
        try {
            if (!writerScheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                LOGGER.warning("Audit writer did not terminate in 10s, forcing shutdown");
                writerScheduler.shutdownNow();
                writerScheduler.awaitTermination(2, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            writerScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        // Final drain after scheduler stopped — picks up anything queued during shutdown
        drainWriteQueue();
        synchronized (writerLock) {
            closeWriter();
            currentLogDate = null;
            currentLogSizeBytes = 0L;
        }
        clearInstance();
        LOGGER.info("Audit log storage shut down. No pending writes.");
    }

    
    static void clearInstance() {
        instance = null;
    }


    // --- File helpers ---

    private File getAuditLogsDir() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) return new File(AUDIT_LOGS_DIR);
        return new File(jenkins.getRootDir(), AUDIT_LOGS_DIR);
    }

    private void ensureAuditLogsDirectoryExists() {
        File dir = getAuditLogsDir();
        if (!dir.exists() && dir.mkdirs()) {
            LOGGER.info("Created audit logs directory: " + dir.getAbsolutePath());
        }
    }

    private File getCurrentLogFile() {
        return new File(getAuditLogsDir(), LOG_FILE_NAME);
    }

    private AuditLoggerConfiguration getConfigurationSafely() {
        try {
            return AuditLoggerConfiguration.get();
        } catch (Exception ignored) {
            return null;
        }
    }

    private LocalDate currentUtcDate() {
        return LocalDate.now(ZoneOffset.UTC);
    }

    private LocalDate toLogDate(long timestampMs) {
        return Instant.ofEpochMilli(timestampMs).atZone(ZoneOffset.UTC).toLocalDate();
    }

    private long estimateSerializedSize(String json) {
        return json.getBytes(StandardCharsets.UTF_8).length + NEWLINE_BYTES;
    }

    private void pruneExpiredLogFiles(AuditLoggerConfiguration config) {
        int retentionDays = config != null ? config.getLogRetentionDays() : 90;
        pruneExpiredLogFiles(getAuditLogsDir(), retentionDays);
    }

    private void pruneExpiredLogFiles(File logDirectory, int retentionDays) {
        if (retentionDays <= 0) {
            return;
        }

        File[] files = logDirectory.listFiles();
        if (files == null || files.length == 0) {
            return;
        }

        LocalDate cutoffDate = currentUtcDate().minusDays(retentionDays);
        for (File file : files) {
            if (!isManagedLogFile(file)) {
                continue;
            }
            if (currentLogFile != null && currentLogFile.equals(file) && currentWriter != null) {
                continue;
            }

            LocalDate fileDate = resolveLogFileDate(file);
            if (fileDate != null && fileDate.isBefore(cutoffDate) && file.delete()) {
                LOGGER.info("Deleted expired audit log: " + file.getName());
            }
        }
    }

    private boolean isManagedLogFile(File file) {
        if (file == null || !file.isFile()) {
            return false;
        }
        String name = file.getName();
        return LOG_FILE_NAME.equals(name)
                || LEGACY_LOG_FILE_NAME.equals(name)
                || ROTATED_LOG_PATTERN.matcher(name).matches()
                || LEGACY_ROTATED_LOG_PATTERN.matcher(name).matches();
    }

    private LocalDate resolveLogFileDate(File file) {
        if (file == null || !file.exists()) {
            return null;
        }

        String name = file.getName();
        if (LOG_FILE_NAME.equals(name)) {
            LocalDate lastEntryDate = readLastEntryDate(file);
            if (lastEntryDate != null) {
                return lastEntryDate;
            }
            return Instant.ofEpochMilli(file.lastModified()).atZone(ZoneOffset.UTC).toLocalDate();
        }
        if (LEGACY_LOG_FILE_NAME.equals(name)) {
            return Instant.ofEpochMilli(file.lastModified()).atZone(ZoneOffset.UTC).toLocalDate();
        }

        Matcher matcher = ROTATED_LOG_PATTERN.matcher(name);
        if (matcher.matches()) {
            try {
                return LocalDate.parse(matcher.group(1), ROTATED_LOG_DATE_FORMAT);
            } catch (Exception e) {
                LOGGER.log(Level.FINE, "Failed to parse rotated audit log date from " + name, e);
                return null;
            }
        }

        Matcher legacyMatcher = LEGACY_ROTATED_LOG_PATTERN.matcher(name);
        if (legacyMatcher.matches()) {
            try {
                return LocalDate.parse(legacyMatcher.group(1), LEGACY_ROTATED_LOG_DATE_FORMAT);
            } catch (Exception e) {
                LOGGER.log(Level.FINE, "Failed to parse legacy rotated audit log date from " + name, e);
            }
        }
        return null;
    }

    private int resolveRotatedLogSegment(File file) {
        if (file == null) {
            return Integer.MAX_VALUE;
        }

        String name = file.getName();
        if (LOG_FILE_NAME.equals(name)) {
            return Integer.MAX_VALUE;
        }
        if (LEGACY_LOG_FILE_NAME.equals(name)) {
            return -1;
        }

        Matcher matcher = ROTATED_LOG_PATTERN.matcher(name);
        if (matcher.matches()) {
            String segment = matcher.group(2);
            return segment == null ? 0 : Integer.parseInt(segment);
        }

        Matcher legacyMatcher = LEGACY_ROTATED_LOG_PATTERN.matcher(name);
        if (legacyMatcher.matches()) {
            return Integer.parseInt(legacyMatcher.group(2));
        }

        return Integer.MAX_VALUE - 1;
    }

    private LocalDate readLastEntryDate(File file) {
        AuditLogEntry lastEntry = null;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                AuditLogEntry parsed = parseJsonLine(line.trim());
                if (parsed != null) {
                    lastEntry = parsed;
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.FINE, "Failed to inspect active audit log date", e);
        }
        return lastEntry != null ? toLogDate(lastEntry.getTimestamp()) : null;
    }

    private List<File> listAuditLogFiles() {
        return listAuditLogFiles(getAuditLogsDir());
    }

    private List<File> listAuditLogFiles(File logDirectory) {
        File[] files = logDirectory.listFiles(this::isManagedLogFile);
        if (files == null || files.length == 0) {
            return Collections.emptyList();
        }

        List<File> logFiles = new ArrayList<>(Arrays.asList(files));
        logFiles.sort(Comparator
                .comparing((File file) -> {
                    LocalDate date = resolveLogFileDate(file);
                    return date != null ? date : LocalDate.MAX;
                })
                .thenComparingInt(this::resolveRotatedLogSegment)
                .thenComparing(File::getName));
        return logFiles;
    }

    private List<AuditLogEntry> loadEntriesFromDisk(String username, String action, Long startTime, Long endTime) {
        return loadEntriesFromDisk(getAuditLogsDir(), username, action, startTime, endTime);
    }

    private List<AuditLogEntry> loadEntriesFromDisk(File logDirectory,
                                                    String username, String action, Long startTime, Long endTime) {
        List<AuditLogEntry> entries = new ArrayList<>();
        for (File file : listAuditLogFiles(logDirectory)) {
            loadEntriesFromFile(file, entries, username, action, startTime, endTime);
        }
        entries.sort(Comparator.comparingLong(AuditLogEntry::getTimestamp));
        return entries;
    }

    private void loadEntriesFromFile(File file, List<AuditLogEntry> entries,
                                     String username, String action, Long startTime, Long endTime) {
        boolean legacy = LEGACY_LOG_FILE_NAME.equals(file.getName());
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                AuditLogEntry entry = legacy ? parseLegacyLine(line.trim()) : parseJsonLine(line.trim());
                if (entry != null && matchesFilters(entry, username, action, startTime, endTime)) {
                    entries.add(entry);
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to load audit logs from " + file.getName(), e);
        }
    }

    private boolean matchesFilters(AuditLogEntry entry, String username, String action, Long startTime, Long endTime) {
        if (entry == null) {
            return false;
        }
        if (username != null && !username.isEmpty() && !entry.getUsername().equalsIgnoreCase(username)) {
            return false;
        }
        if (action != null && !action.isEmpty() && !matchesActionFilter(entry.getAction(), action)) {
            return false;
        }
        if (startTime != null && entry.getTimestamp() < startTime) {
            return false;
        }
        return endTime == null || entry.getTimestamp() <= endTime;
    }

    private boolean matchesActionFilter(String entryAction, String requestedAction) {
        if (entryAction == null || requestedAction == null) {
            return false;
        }
        if (entryAction.equalsIgnoreCase(requestedAction)) {
            return true;
        }
        return "SCRIPT_CONSOLE_ACCESS".equalsIgnoreCase(requestedAction)
                && "SCRIPT_CONSOLE_ACCESSED".equalsIgnoreCase(entryAction);
    }

    private int getBatchSize() {
        AuditLoggerConfiguration config = getConfigurationSafely();
        return config != null ? config.getBatchWriteSize() : DEFAULT_BATCH_SIZE;
    }

    // --- Load from disk on startup ---

    private void loadRecentLogs() {
        try {
            List<AuditLogEntry> entries = loadEntriesFromDisk(null, null, null, null);

            bufferLock.writeLock().lock();
            try {
                memoryBuffer.clear();
                int start = Math.max(0, entries.size() - MAX_ENTRIES_IN_MEMORY);
                for (int i = start; i < entries.size(); i++) {
                    memoryBuffer.addLast(entries.get(i));
                }
            } finally {
                bufferLock.writeLock().unlock();
            }
            LOGGER.info("Loaded " + memoryBuffer.size() + " recent audit log entries from disk");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to load audit logs from disk", e);
        }
    }

    private AuditLogEntry parseJsonLine(String line) {
        try {
            JsonObject obj = JsonParser.parseString(line).getAsJsonObject();
            String user = getStr(obj, "user", "SYSTEM");
            String action = getStr(obj, "action", "UNKNOWN");
            String target = getStr(obj, "target", "unknown");
            String details = getStr(obj, "details", "");

            if (action.isEmpty() || "UNKNOWN".equals(action)) return null;

            // Restore original timestamp from persisted epoch millis
            long ts = System.currentTimeMillis();
            if (obj.has("timestampMs") && !obj.get("timestampMs").isJsonNull()) {
                ts = obj.get("timestampMs").getAsLong();
            }

            AuditLogEntry entry = new AuditLogEntry(user, action, target, details, ts);
            if (obj.has("sourceIp")) entry.setSourceIp(getStr(obj, "sourceIp", null));
            if (obj.has("authMethod")) entry.setAuthMethod(getStr(obj, "authMethod", null));
            if (obj.has("triggerType")) entry.setTriggerType(getStr(obj, "triggerType", null));
            if (obj.has("sessionId")) entry.setSessionId(getStr(obj, "sessionId", null));
            if (obj.has("userAgent")) entry.setUserAgent(getStr(obj, "userAgent", null));
            if (obj.has("severity")) entry.setSeverity(getStr(obj, "severity", "INFO"));
            return entry;
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Failed to parse JSON log line", e);
            return null;
        }
    }

    private AuditLogEntry parseLegacyLine(String line) {
        if (!line.startsWith("[")) return null;
        try {
            int endBracket = line.indexOf(']');
            if (endBracket < 0) return null;
            String rest = line.substring(endBracket + 1).trim();
            String[] parts = rest.split("\\|", 5);
            if (parts.length >= 4) {
                return new AuditLogEntry(parts[0].trim(), parts[1].trim(),
                        parts[2].trim(), parts[3].trim());
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static String getStr(JsonObject obj, String key, String defaultVal) {
        if (!obj.has(key) || obj.get(key).isJsonNull()) return defaultVal;
        String val = obj.get(key).getAsString();
        return (val != null && !val.isEmpty()) ? val : defaultVal;
    }
}
