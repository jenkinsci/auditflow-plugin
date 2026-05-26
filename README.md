# AuditFlow – Jenkins Audit Logs You Can Actually Understand

AuditFlow is a lightweight Jenkins plugin that turns raw audit logs into a clean, searchable dashboard.

Instead of digging through system logs, you can instantly see:
- Who triggered a build
- What changed in jobs or configuration
- When credentials were created or updated
- Where actions originated from (IP, auth type)

Built for real-world debugging and audit visibility.

---

## 🚀 Why AuditFlow?

Most Jenkins audit plugins focus on logging.

**AuditFlow focuses on visibility.**

- No need for external tools (ELK, Splunk)
- Built-in UI with filtering and search
- Works out-of-the-box
- Designed for engineers, not auditors

---

## Screenshots

### Audit Dashboard
![Audit Dashboard](src/screenshots/07-audit-dashboard.png)

### Audit Log Entries
![Audit Log Entries](src/screenshots/06-audit-log-entries.png)

### Manage Jenkins – AuditFlow Logs
![Manage Jenkins](src/screenshots/08-manage-jenkins.png)

### Configuration – Event Categories
![Event Categories](src/screenshots/01-config-event-categories.png)

### Configuration – Risk Detection
![Risk Detection](src/screenshots/02-config-risk-detection.png)

### Configuration – Log Retention & Dashboard
![Retention & Dashboard](src/screenshots/03-config-retention-dashboard.png)

### Configuration – Export & REST API
![Export & API](src/screenshots/04-config-export-api.png)

### Configuration – Optimization & Data Masking
![Optimization & Masking](src/screenshots/05-config-optimization-masking.png)

---

## Features

- **Paginated Audit Viewer** – 100/500/1000 per page with filtering and search
- **Color-Coded Severity** – Visual badges (Critical, High, Medium, Low, Info)
- **IP Address Tracking** – Source IP capture with async caching
- **Export** – CSV, JSON, TXT with formula-injection protection
- **REST API** – Query logs at `/auditflow/api/logs`
- **Risk Detection** – Failed login tracking, off-hours alerts, production job changes
- **Log Rotation** – Automatic rotation with configurable retention
- **Data Masking** – Mask tokens, emails, credit cards in log details
- **Async & Non-Blocking** – Zero impact on build performance

## Requirements

- Jenkins 2.361.4+
- Java 11+

## Installation

### Build from Source

```bash
mvn clean package -DskipTests
```

Output: `target/auditflow-<version>.hpi`

### Install in Jenkins

1. **Manage Jenkins -> Plugins -> Advanced -> Upload Plugin**
2. Upload `target/auditflow-<version>.hpi`
3. Restart Jenkins

Or copy directly:

```bash
cp target/auditflow-<version>.hpi $JENKINS_HOME/plugins/auditflow.jpi
systemctl restart jenkins
```

## Configuration

**Manage Jenkins -> Configure System -> AuditFlow Configuration**

### Event Categories

| Category | Events |
|----------|--------|
| Authentication | LOGIN, LOGOUT, FAILED_LOGIN, API_AUTH, SSO_LOGIN |
| Builds | BUILD_STARTED, BUILD_COMPLETED, BUILD_DELETED |
| Jobs | JOB_CREATED, JOB_UPDATED, JOB_DELETED, JOB_RENAMED, JOB_COPIED |
| Credentials | CREDENTIAL_CREATED, CREDENTIAL_ACCESSED, CREDENTIAL_UPDATED, CREDENTIAL_DELETED |
| System | USER_CONFIG_UPDATED, SECURITY_REALM_CHANGED |
| Plugins | PLUGIN_INSTALLED, PLUGIN_UNINSTALLED |

### Severity & Badge Colors

| Severity | Color | Usage |
|----------|-------|-------|
| CRITICAL | Red (#a12d35) | Failed logins, security breaches |
| HIGH | Orange (#b85a10) | Deletions, major config changes |
| MEDIUM | Blue (#2563a8) | Logins, configuration updates |
| LOW | Green (#146b43) | Job/credential creation, builds |
| INFO | Grey (#5a6268) | API auth, system events (muted) |

### Log Storage

- **Location:** `$JENKINS_HOME/auditflow-logs/audit.jsonl`
- **Format:** JSON Lines (one JSON object per line)
- **Buffer:** 10,000 entry in-memory ring buffer
- **Rotation:** Configurable max file size and retention days

## Audit Log Viewer

Access: **Manage Jenkins -> AuditFlow Logs**

- Filter by action, user, date range
- Toggle "User-Initiated Only" to hide system noise
- Paginate with 100/500/1000/All per page
- Export filtered logs as CSV, JSON, or TXT

## REST API

```bash
curl -u admin:token \
  'http://localhost:8080/auditflow/api/logs?user=john&action=LOGIN'
```

Parameters: `user`, `action`, `startTime`, `endTime`

### Response

```json
{
  "status": "success",
  "count": 42,
  "logs": [
    {
      "timestamp": 1741086645000,
      "username": "john",
      "action": "LOGIN",
      "target": "Jenkins",
      "details": "User authenticated from 192.168.1.100",
      "severity": "LOW",
      "sourceIp": "192.168.1.100",
      "userAgent": "Mozilla/5.0..."
    }
  ]
}
```

## Event Types

### Authentication Events
- `LOGIN` - User login successfully
- `LOGOUT` - User logout
- `LOGIN_FAILED` - Authentication failed
- `API_AUTH` - API token or basic auth used

### Build Events
- `BUILD_STARTED` - Build queued and starting
- `BUILD_COMPLETED` - Build finished with result
- `BUILD_DELETED` - Build record deleted

### Job Events
- `JOB_CREATED` - New job/pipeline created
- `JOB_UPDATED` - Job configuration modified
- `JOB_DELETED` - Job deleted
- `JOB_RENAMED` - Job renamed
- `JOB_COPIED` - Job template copied

### Configuration Events
- `CONFIG_CHANGED` - System or job configuration saved
- `CREDENTIAL_UPDATED` - Credentials modified
- `PLUGIN_INSTALLED` - Plugin installed or updated

## Log Entry Format

```json
{
  "timestamp": "2026-04-01T14:09:30Z",
  "timestampMs": 1775052570646,
  "user": "admin",
  "action": "BUILD_COMPLETED",
  "target": "production-deploy",
  "details": "Build #42 completed: SUCCESS (duration: 2m 15s)",
  "sourceIp": "192.168.1.100",
  "authMethod": "form",
  "triggerType": "manual",
  "sessionId": "ABC123",
  "userAgent": "Mozilla/5.0...",
  "severity": "LOW"
}
```

## Performance

| Metric | Value |
|--------|-------|
| Logging latency | <1 ms (async) |
| Memory footprint | 10-50 MB (configurable) |
| Max entries buffered | 10,000 |
| Log rotation check | Hourly |
| Build execution impact | <0.1% |

## Project Structure

```
src/main/java/io/jenkins/plugins/auditlogger/
+-- AuditLoggerPlugin.java          # Plugin entry point
+-- AuditLoggerConfiguration.java   # Global configuration
+-- AuditLoggerManagementLink.java  # Web UI + exports
+-- AuditLogStorage.java            # Async storage engine
+-- AuditLogEntry.java              # Log entry model
+-- AuditLogEntrySerializer.java    # JSON serializer
+-- AuditLogRestApi.java            # REST API endpoint
+-- AuditLogIndex.java              # Fast indexed queries
+-- AuditSecurityListener.java      # Auth events
+-- AuditRunListener.java           # Build events
+-- AuditItemListener.java          # Job lifecycle
+-- AuditSaveableListener.java      # Config changes
+-- AuditSessionListener.java       # Session tracking
+-- AuditRequestCapture.java        # HTTP request capture
+-- AuditAlertEngine.java           # Rule-based alerts
+-- AnomalyDetector.java            # Anomaly detection
+-- AuditMetricsEngine.java         # Metrics collection
+-- BatchWriteBuffer.java           # Batch writer
+-- ComplianceReportGenerator.java  # Compliance reports
+-- DataMasker.java                 # PII masking
+-- LogRotationService.java         # Log rotation
+-- RequestHolder.java              # Thread-local + IP cache
+-- StartupPhaseManager.java        # Startup grace period
```

## Compatibility

- **Jenkins:** 2.361.4 or later, with `verify` passing against 2.440 and live regression validation completed on 2.541.3
- **Java:** 11 or later
- **Deployment:** Standalone, Docker, Kubernetes, Cloud-managed Jenkins

## License

MIT License.

## Support

- **GitHub:** https://github.com/jenkinsci/auditflow-plugin
- **Issues:** Report bugs and feature requests on GitHub

## Version History

### 1.1.1
- Refined Insights to summarize current-day activity while honoring the active filters
- Kept anomaly detection and the anomaly row disabled while still using thresholds for Insights prioritization
- Preserved non-visible configuration values across Configure System save cycles
- Validated config round-trips and log rotation behavior live on Jenkins 2.541.3

### 1.1.0
- Verified plugin build compatibility against Jenkins 2.440
- Live regression validation completed for credentials, plugin lifecycle events, authentication events, and build outcomes
- Fixed timestamp reload drift so persisted events keep their original audit time after restart
- Fixed credential mutation detection on the first post-startup change
- Fixed plugin manager route handling for modern `/plugin/{name}/...` endpoints
- Removed runtime anomaly detection work from the audit hot path to keep write latency predictable under load

### 1.0.0
- Initial public release
