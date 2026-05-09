# Audit Log Migration Plan - AuditFlow Plugin

## Overview
Migrate historical audit logs from another Jenkins controller to current AuditFlow instance with one-time import and UI display capability.

## Key Considerations
- Source logs may be incomplete (missing IP address, auth method, user agent, etc.)
- Handle multiple source formats (JSON Lines, text logs, other audit plugins)
- Preserve timestamps and core audit information
- Mark imported logs as "MIGRATED" for distinction
- No real-time sync needed - one-time operation
- Maintain data integrity and plugin performance

---

## Phase 1: Source Log Analysis & Extraction

### 1.1 Identify Source Log Formats
- [ ] Determine if source uses AuditFlow (JSON Lines) or legacy format
- [ ] Check if other audit plugins present (Jenkins Audit Trail Plugin, core audit logs)
- [ ] Identify exact file locations and format specifications
- [ ] Validate sample logs to understand field mapping

### 1.2 Access Strategy
- [ ] SSH/remote access to source controller's `$JENKINS_HOME/auditflow-logs/`
- [ ] OR export logs via source controller REST API (if available)
- [ ] OR use Jenkins script console to dump logs to portable format
- [ ] Verify log count and date range

---

## Phase 2: Data Mapping & Normalization

### 2.1 Field Mapping Strategy

**Source → AuditLogEntry mapping:**
- Required fields:
  - `timestamp` → `timestampMs` (convert to epoch millis if needed)
  - User identification → `username` (use "UNKNOWN" if missing)
  - Event type → `action` (standardize action names)
  - Target (job/item) → `target`
  
- Optional fields (may be missing):
  - `sourceIp` → Mark as "MIGRATED" or empty if unavailable
  - `authMethod` → Set to "migrated" or null
  - `userAgent` → Set to "migrated" or null
  - `triggerType` → Best effort extraction
  - `sessionId` → Generate or mark as "n/a"

### 2.2 Handle Missing Data
- [ ] Define defaults for missing fields (null vs empty string vs "MIGRATED")
- [ ] Add metadata field or flag to mark imported logs as "migrated"
- [ ] Store migration source info (e.g., "imported_from_controller_2")
- [ ] Ensure severity is properly derived from action

---

## Phase 3: Intermediate Format Creation

### 3.1 Create Migration Adapter
Build a JSON Lines converter that:
- Reads source format
- Maps to AuditLogEntry JSON structure
- Fills missing fields with defaults
- Outputs normalized JSONL file

**Example output format:**
```json
{"timestamp":"2026-04-01T10:30:00Z","timestampMs":1775050200000,"user":"admin","action":"JOB_CREATED","target":"my-job","details":"Job created via UI","sourceIp":"","authMethod":"migrated","userAgent":"migrated","severity":"LOW","migrationSource":"controller_02"}
```

### 3.2 Validation
- [ ] Parse and validate each line
- [ ] Log conversion errors/warnings
- [ ] Verify field completeness
- [ ] Calculate total entries count

---

## Phase 4: Data Import Mechanism

### 4.1 Create Import Service
New class: `AuditLogMigrationService`

**Responsibilities:**
- Accept normalized JSONL file path
- Batch parse entries (1000+ per batch)
- Validate entries before import
- Progress tracking/logging
- Error handling and rollback capability
- Update in-memory buffer and disk storage

**Key methods:**
```java
public MigrationResult importFromFile(File jsonlFile, int batchSize)
public MigrationResult importFromUrl(String sourceUrl, Credentials)
public void clearMigrationCache()
public List<String> validateMigrationFile(File jsonlFile)
```

### 4.2 Batch Import Logic
- Read JSONL in batches
- Parse each batch
- Add to AuditLogStorage via `addEntry()` or new batch method
- Ensure proper ordering by timestamp
- Handle disk writes (rotation awareness)
- Progress logging

### 4.3 Duplicate Detection (Optional)
- [ ] Create hash of `timestamp + username + action + target` to detect duplicates
- [ ] Option to skip duplicates or merge
- [ ] Log duplicate count

---

## Phase 5: UI/Configuration for Migration

### 5.1 Admin UI Page
Add new page: "Manage Jenkins" → "AuditFlow" → "Audit Migration"

**Features:**
- Upload JSONL file directly OR paste URL
- Preview first 10 entries
- Validation report (errors, warnings, completeness)
- Confirm import
- Real-time progress bar
- Result summary (imported count, errors, warnings)
- Option to download error report

### 5.2 REST API Endpoint
```
POST /rest/auditlog/migrate
Content-Type: application/json

{
  "sourceType": "jsonl_file" | "jsonl_url" | "legacy_text",
  "sourceUrl": "http://source-controller:8080/...",
  "credential": "jenkins_credential_id",
  "batchSize": 1000,
  "skipDuplicates": true
}

Response:
{
  "status": "IN_PROGRESS" | "COMPLETED" | "FAILED",
  "progress": 45.5,
  "totalCount": 5000,
  "processedCount": 2275,
  "errorCount": 0,
  "warningCount": 125,
  "errors": [...]
}
```

---

## Phase 6: Display & Filtering

### 6.1 Mark Imported Logs in UI
- [ ] Add "Source" column in audit dashboard (e.g., "LIVE", "MIGRATED_CTRL_2")
- [ ] Filter badge/icon for migrated logs
- [ ] Optional separate view for migrated logs
- [ ] Search capability: `source:migrated` or `source:live`

### 6.2 Completeness Indicator
- [ ] Show warning badge if critical fields missing (IP, auth method)
- [ ] Hover tooltip: "Imported from [source], some fields unavailable"
- [ ] Toggle to hide/show incomplete entries

---

## Phase 7: Implementation Breakdown

### Core Classes to Create/Modify
1. **New: `AuditLogMigrationService.java`**
   - Parse, validate, import logic
   
2. **New: `MigrationResult.java`**
   - Status, counts, errors tracking
   
3. **Modify: `AuditLogEntry.java`**
   - Add `sourceOrigin` field (default: "live", can be "migrated_control_2", etc.)
   - Add `setSourceOrigin()` setter
   
4. **Modify: `AuditLogStorage.java`**
   - Add `importBatch(List<AuditLogEntry>)` method
   - Add deduplication logic (optional)
   
5. **New: `AuditMigrationPage.java`** (Groovy view)
   - UI form + progress display
   
6. **Modify: `AuditLoggerManagementLink.java`**
   - Add migration admin UI link
   
7. **New: `AuditMigrationRestApi.java`**
   - REST endpoint for migration

### Supporting Classes
- **`LegacyAuditParser.java`** - Handle non-AuditFlow formats
- **`AuditLogValidator.java`** - Validate entries pre-import
- **`MigrationProgressTracker.java`** - Track async progress

---

## Phase 8: Error Handling & Edge Cases

### 8.1 Error Scenarios
- [ ] Malformed JSON in source
- [ ] Missing required fields (username, action)
- [ ] Invalid timestamps
- [ ] Encoding issues
- [ ] File too large (memory/disk)
- [ ] Duplicate entries
- [ ] Network timeouts (if remote import)

### 8.2 Rollback Strategy
- [ ] Keep migration log file separate initially
- [ ] Option to cancel mid-migration
- [ ] Restore from backup if needed
- [ ] Log all import details for audit trail

---

## Phase 9: Testing Strategy

### 9.1 Unit Tests
- Parse various source formats
- Field mapping accuracy
- Missing field handling
- Duplicate detection
- Batch processing

### 9.2 Integration Tests
- Import 10K, 100K entries
- Verify storage integrity
- UI display correctness
- Performance benchmarks
- Recovery from failures

### 9.3 UAT Scenarios
- Test with real source logs
- Validate UI workflow
- Check performance with large datasets
- Verify no impact on live logging

---

## Phase 10: Documentation & Runbook

### 10.1 User Guide
- Step-by-step import process
- Handling missing data
- Verification checklist
- Troubleshooting common issues

### 10.2 Architecture Doc
- Migration flow diagram
- Data model changes
- Performance considerations
- Backup/recovery procedures

---

## Implementation Sequence

1. **Week 1:** Phases 1-3 (Analyze source, create adapter, validation)
2. **Week 2:** Phase 4 (Import service implementation)
3. **Week 3:** Phase 5 (UI/REST API)
4. **Week 4:** Phase 6 (Display features), Phase 8 (Error handling)
5. **Week 5:** Phase 9 (Testing), Phase 10 (Documentation)

---

## Success Criteria

- [x] All source logs successfully imported
- [x] No data loss or corruption
- [x] Imported logs viewable and searchable in UI
- [x] Performance: Import 100K entries < 5 minutes
- [x] Memory usage: < 500MB during import
- [x] Clear distinction between live and migrated logs
- [x] Comprehensive error reporting
- [x] Graceful handling of incomplete data

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **One-time import** | No real-time sync needed; simpler, safer |
| **Mark imported logs** | Distinguish historical from live data |
| **Handle missing fields** | IP/auth may not exist in legacy logs—use defaults |
| **Batch processing** | Import 1000+ entries per batch for performance |
| **REST API + Web UI** | Flexibility: API for automation, UI for manual ops |
| **Validation layer** | Catch errors before storage; detailed error reporting |

---

## Data Handling for Missing Fields

```
sourceIp        → Empty or "MIGRATED" flag (shown in UI)
authMethod      → Set to "migrated" or null
userAgent       → Set to "migrated" or null
timestamp       → REQUIRED (extract from source, use epoch if needed)
username        → REQUIRED (use "UNKNOWN" as fallback)
action          → REQUIRED (standardize action names)
target          → REQUIRED (job/item name)
severity        → Derived from action
sourceOrigin    → NEW FIELD: "migrated_controller_02" or "live"
```

---

## Next Steps Before Implementation

1. **Clarify source format:**  
   - Is the other controller running AuditFlow (JSON Lines)?  
   - Or legacy Jenkins audit logs?  
   - Or another audit plugin?

2. **Determine access method:**  
   - Direct file copy, REST API, or script console dump?

3. **Define field mapping:**  
   - What source fields map to which AuditLogEntry fields?

4. **Set retention policy:**  
   - Keep all imported logs or archive old ones?

5. **Validate with sample data:**  
   - Export 100-200 logs from source
   - Test parsing and field mapping
   - Verify timestamp accuracy
