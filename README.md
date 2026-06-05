# AuditFlow – Jenkins Audit Logging Plugin

AuditFlow is a lightweight Jenkins plugin that provides comprehensive audit logging with a searchable dashboard for visibility and compliance. Capture authentication events, build activities, job configuration changes, credential operations, and plugin management in a clean, queryable interface.

## What is AuditFlow?

AuditFlow turns raw Jenkins audit logs into actionable visibility. Instead of searching through system logs, you get:

- Complete audit trail of who did what and when
- Search and filter capabilities across all audit events
- Real-time dashboard with key metrics and statistics
- Export functionality for compliance and analysis
- REST API for integration with external systems
- Configurable retention policies for log management

## Why AuditFlow?

- **Out-of-the-box visibility** – No external tools required; built-in dashboard provides immediate insights
- **Non-intrusive** – Asynchronous logging with zero impact on build performance
- **Comprehensive tracking** – Captures authentication, builds, configurations, credentials, plugins, and more
- **Enterprise-ready** – Designed for teams needing audit compliance and security visibility
- **Flexible configuration** – Enable/disable event categories based on your needs

## Features

- **Real-time Audit Dashboard** – View events with pagination (100/500/1000 rows per page)
- **Advanced Search & Filtering** – Filter by user, action, target, timestamp, and more
- **Risk Indicators** – Color-coded severity badges and anomaly detection
- **IP Address Tracking** – Capture source IP for all events
- **Export Capabilities** – CSV and JSON export with formula-injection protection
- **REST API** – Query audit logs programmatically at `/auditflow/api/logs`
- **Configurable Event Categories** – Choose what to track (authentication, builds, jobs, credentials, plugins, system config, nodes, API calls)
- **Automatic Log Rotation** – Configurable retention policies (default 90 days)
- **Data Masking** – Optional masking of tokens, credit cards, and sensitive information
- **Dashboard Customization** – Configure time zones, display metrics, and visible counters
- **Non-blocking Performance** – Async batch writes with configurable batch size and flush intervals

## Configuration

Access configuration at: **Manage Jenkins** → **System** → **AuditFlow Configuration**

### What to Track (Event Categories)

Choose which events to capture and store:

- **Authentication** – Login, logout, failed login, API authentication (Enabled by default)
- **Builds** – Build start, complete, fail, abort, delete (Enabled by default)
- **Job Changes** – Job create, rename, copy, move, delete, config updates (Enabled by default)
- **Credentials** – Credential create, update, delete, usage during builds (Enabled by default)
- **Plugins** – Plugin install, update, remove, enable, disable (Enabled by default)
- **System Configuration** – Security and global settings (Disabled by default)
- **Nodes** – Node create, delete, config changes (Disabled by default)
- **API Calls** – REST API activity (Disabled by default)

### Dashboard Display Settings

Customize how events are displayed:

- **Stats counters row** – Show daily event totals (Enabled by default)
- **Risk level badges** – Color-coded severity indicators (Disabled by default)
- **Display time zone** – Select your preferred timezone (default: UTC)
- **Visible stats counters** – Choose which metrics appear (Total Events, Logins, Failed Logins, Builds, Job Events, Config Changes)

### Export & API Options

- **CSV Export** – Enable/disable CSV export functionality (Enabled by default)
- **JSON Export** – Enable/disable JSON export functionality (Enabled by default)
- **REST API endpoint** – Query logs at `/auditflow/api` (Enabled by default)

### Advanced Settings

#### Log Retention

- **Keep logs for (days)** – Default 90 days (0 = keep forever)
- **Max log file size (MB)** – Default 50 MB per file
- **Auto-rotate when size exceeded** – Automatically rotate logs when size threshold is reached

#### Performance & Optimization

- **Startup grace period (seconds)** – Suppress config-reload noise during startup (5–300 seconds, default 120)
- **Batch write size** – Number of events batched before writing (default 100)
- **Batch flush interval (seconds)** – Maximum time before flushing batch (default 5 seconds)
- **Note:** Anomaly detection is temporarily disabled to keep write performance predictable

#### Privacy & Data Masking

- **Mask tokens and secrets** – Hide API tokens and credentials in log details (Enabled by default)
- **Mask email addresses** – Anonymize user emails (Disabled by default)
- **Mask credit card numbers** – Hide payment card numbers (Enabled by default)

## Screenshots

### Main Audit Dashboard
![Main Dashboard](src/screenshots/01-main-dashboard.png)

Dashboard overview showing today's event metrics, search/filtering interface, and a table of recent audit entries with timestamp, user, action, target, details, source IP, and authentication trigger.

### Insights Panel
![Insights Panel](src/screenshots/02-insights-panel.png)

Quick summary of top issues and risky activity detected today, including failed login attempts, plugin changes, and most active users.

### Export Options
![Export Menu](src/screenshots/03-export-menu.png)

Export functionality supporting CSV and JSON formats for compliance, analysis, and external tool integration.

### Configuration – What to Track
![What to Track](src/screenshots/04-config-what-to-track.png)

Enable/disable specific audit event categories including authentication, builds, job changes, credentials, plugins, system configuration, nodes, and API calls.

### Configuration – Dashboard Display
![Dashboard Display](src/screenshots/05-config-dashboard-display.png)

Customize dashboard appearance including stats counters, risk badges, timezone selection, and which metrics are visible.

### Configuration – Export & API
![Export & API](src/screenshots/06-config-export-api.png)

Control availability of export formats (CSV, JSON) and REST API endpoint for external integrations.

### Configuration – Log Retention
![Log Retention](src/screenshots/07-config-advanced-retention.png)

Configure how long logs are retained, maximum log file size, and automatic rotation settings.

### Configuration – Performance & Privacy
![Performance & Privacy](src/screenshots/08-config-performance-privacy.png)

Advanced settings for batch processing, startup grace period, and data masking options to balance performance with privacy requirements.

## External Logging Integration

For immutable log storage and long-term retention, consider sending AuditFlow logs to external logging platforms:

- **Splunk** – Use the Splunk HTTP Event Collector (HEC) to forward logs
- **CloudWatch** – Push logs to AWS CloudWatch for centralized monitoring
- **Datadog** – Ship logs to Datadog for analysis and alerting
- **ELK Stack** – Send logs to Elasticsearch for advanced querying and visualization
- **Sumo Logic** – Forward logs to Sumo Logic for security and compliance
- **LogStash/Fluentd** – Use log forwarders to send logs to your SIEM

External logging provides:
- Audit log immutability (protection against tampering)
- Long-term retention beyond plugin storage limits
- Centralized log analysis across infrastructure
- Advanced search, alerting, and compliance reporting

## Reporting Issues

If you encounter any issues, bugs, or have feature requests:

1. Check existing issues in the repository
2. Provide detailed reproduction steps
3. Include Jenkins version, Java version, and plugin version
4. Share relevant log excerpts from Jenkins logs

Issues reported will be reviewed and fixed in upcoming releases. Community contributions are also welcome.

## Version Information

**Current Version:** 1.0.0

**License:** MIT

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

- **Deployment:** Standalone, Docker, Kubernetes, Cloud-managed Jenkins

## License

MIT License.

## Support

- **GitHub:** https://github.com/jenkinsci/auditflow-plugin
- **Issues:** Report bugs and feature requests on GitHub

## Version History

### 1.0.0
- Initial public release
