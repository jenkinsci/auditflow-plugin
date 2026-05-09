 # AuditFlow – Jenkins Audit Logs You Can Actually Understand

**Stop digging through Jenkins logs. Start understanding what's happening.**

AuditFlow is a lightweight Jenkins plugin that transforms raw audit logs into a clean, searchable dashboard. Instead of hunting through system logs to figure out what happened, you get instant visibility into:

- **Who** triggered a build or made changes
- **What** changed in jobs and configurations
- **When** credentials were created, updated, or accessed
- **Where** actions came from (source IP, authentication method)

It's built for real-world debugging and compliance auditing—without the complexity of external tools.

---

## Why Use AuditFlow?

**Most Jenkins audit plugins just log things. AuditFlow helps you understand them.**

- ⚡ **No external tools needed** – No ELK, Splunk, or complex setup required
- 🎯 **Works out-of-the-box** – Install, configure once, and get instant visibility
- 👀 **Built for engineers** – Clean UI, filtering, search—designed for actual use, not just compliance checkboxes
- 🚀 **Zero performance impact** – Async logging means your builds stay fast
- 📊 **Visual insights** – Color-coded severity, risk detection, and anomaly alerts

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

**Real audit visibility, not just logs:**

- **Searchable Dashboard** – Find exactly what you need with 100/500/1000 entries per page, filtering, and full-text search
- **Color-Coded Severity** – Visual badges (Critical, High, Medium, Low, Info) make problems jump off the screen
- **IP Address Tracking** – See where every action came from with automatic IP-to-hostname resolution
- **Smart Export** – Download logs as CSV, JSON, or TXT with protection against formula injection attacks
- **REST API** – Query logs programmatically at `/auditflow/api/logs` for integrations
- **Anomaly Detection** – Alerts on suspicious patterns like off-hours changes or repeated failed logins
- **Automatic Log Rotation** – Old logs clean up themselves—configurable by size and retention days
- **Data Masking** – Tokens, passwords, and credit cards are automatically masked in log details
- **Build-Safe Async** – Everything runs asynchronously in the background with <0.1% performance impact on builds

## Requirements

- Jenkins 2.361.4+
- Java 11+

## Installation

### Option 1: Build from Source

If you want to build the plugin yourself:

```bash
mvnw.cmd clean package -DskipTests
```

This generates `target/auditflow.hpi` ready to install.

### Option 2: Install in Jenkins

**Via Jenkins UI (Easiest):**
1. Go to **Manage Jenkins** → **Manage Plugins** → **Advanced settings**
2. Upload your `auditflow.hpi` file
3. Restart Jenkins

**Via Command Line (Linux/Mac):**
```bash
cp auditflow.hpi $JENKINS_HOME/plugins/
systemctl restart jenkins
```

**Via Docker:**
```bash
docker run -v /your/plugins:/var/jenkins_home/plugins jenkins/jenkins:latest
```
Just drop `auditflow.hpi` in your plugins volume.

After restart, you'll see **AuditFlow Logs** in the Manage Jenkins menu.

## Configuration

**First time setup:** Go to **Manage Jenkins** → **Configure System** → Find **AuditFlow Configuration**

Most settings work out-of-the-box, but here's what you can customize:

### Event Categories

Choose what gets logged. By default, all are tracked:

| Category | What Gets Logged | Use This For |
|----------|---|---|
| **Authentication** | Logins, logouts, failed auth attempts | Security audits, detecting break-in attempts |
| **Builds** | Build started/completed/deleted events | Understanding job history and troubleshooting |
| **Jobs** | Job creation, updates, deletions, renames | Configuration change tracking |
| **Credentials** | When credentials are created, accessed, updated | Compliance and access auditing |
| **System** | System config changes, security settings | Major infrastructure changes |
| **Plugins** | Plugin installs and uninstalls | Software inventory tracking |

### Severity Levels

Events are color-coded so critical stuff stands out:

| Severity | Color | Examples |
|----------|-------|----------|
| **CRITICAL** | Red | Failed logins, security breaches |
| **HIGH** | Orange | Deleting jobs or major config changes |
| **MEDIUM** | Blue | Normal logins and config updates |
| **LOW** | Green | Job/credential creation, successful builds |
| **INFO** | Grey | System events and API access (usually muted) |

### Log Storage

Logs are stored locally in your Jenkins home:
- **Location:** `$JENKINS_HOME/auditflow-logs/audit.jsonl`
- **Format:** One JSON object per line (searchable, parseable)
- **Memory Usage:** 10,000 entries kept in-memory ring buffer (fast searches)
- **Auto-Cleanup:** Set max file size and how many days to keep logs

## Using the Audit Dashboard

**Access it:** Go to **Manage Jenkins** → **AuditFlow Logs**

**What you can do:**

- **Search** – Find any event by action, user, job name, IP address
- **Filter** – View only what matters (failed logins, production changes, etc.)
- **Hide the Noise** – Toggle "User-Initiated Only" to remove automated system events
- **Paginate** – View 100, 500, 1000, or all entries at once
- **Export** – Download filtered results as CSV, JSON, or TXT for reports or external systems
- **Date Range** – Jump to a specific timeframe instantly

**Common use cases:**
- _"Who changed this job?"_ – Search by job name, see all modifications
- _"When was that credential updated?"_ – Search by credential, see access history
- _"Did anyone log in from outside our network?"_ – Filter by failed logins or unusual IPs
- _"Generate a compliance report"_ – Export for your auditors

## REST API (For Integration)

**Want to pull audit logs programmatically?** Use the REST API:

```bash
curl -u admin:your_api_token \
  'http://your-jenkins.com/auditflow/api/logs?user=john&action=LOGIN&startTime=2026-01-01'
```

**Query Parameters:**
- `user` – Filter by username
- `action` – Filter by event type (LOGIN, BUILD_STARTED, JOB_CREATED, etc.)
- `startTime` – Start of date range (ISO 8601 format: 2026-01-01 or milliseconds)
- `endTime` – End of date range

**Example Response:**
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

**Use this to:**
- Integrate with SIEM systems
- Build custom dashboards
- Trigger alerts based on events
- Feed data into compliance tools

## Event Types Reference

**When you look up logs, these are the events you'll see:**

### Login & Security
- `LOGIN` – User successfully logged in
- `LOGOUT` – User logged out
- `LOGIN_FAILED` – Authentication attempt failed (potential breach attempt)
- `API_AUTH` – Someone used an API token or basic auth

### Build Activity
- `BUILD_STARTED` – Build queued and started executing
- `BUILD_COMPLETED` – Build finished (with result: SUCCESS, FAILURE, etc.)
- `BUILD_DELETED` – Build record deleted from Jenkins

### Job Management
- `JOB_CREATED` – New job or pipeline created
- `JOB_UPDATED` – Job configuration was modified
- `JOB_DELETED` – Job was permanently deleted
- `JOB_RENAMED` – Job renamed
- `JOB_COPIED` – Job duplicated from a template

### Configuration Changes
- `CONFIG_CHANGED` – System or job configuration saved
- `CREDENTIAL_UPDATED` – Stored credentials were changed
- `CREDENTIAL_ACCESSED` – Someone used a stored credential
- `PLUGIN_INSTALLED` – New plugin installed or existing one updated
- `PLUGIN_UNINSTALLED` – Plugin removed

**Tip:** Use filters to focus on the events that matter for your use case.

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

## Performance & Resource Impact

**Won't slow down your builds:**

| Metric | Performance | What It Means |
|--------|---|---|
| **Logging Speed** | <1 ms | Audit entries are recorded instantly in memory |
| **Memory Usage** | 10-50 MB | Configurable buffer, easily fits on any machine |
| **Max Buffered** | 10,000 entries | Typical deployment handles weeks of logs in memory |
| **Build Impact** | <0.1% | Completely invisible to build performance |
| **Log Rotation Check** | Hourly | Old logs cleaned up automatically without blocking |

**The bottom line:** AuditFlow is designed to be transparent—you get complete audit visibility without sacrificing Jenkins performance.

## How It's Built

**For developers who want to understand the architecture:**

```
Core Components:
├── AuditLoggerPlugin            # Entry point and initialization
├── AuditLoggerConfiguration     # Where users configure settings
├── AuditLogStorage              # Async engine that writes events to disk
├── AuditLogIndex                # Fast in-memory index for searching
└── AuditLogRestApi              # REST endpoint for programmatic access

Event Capture:
├── AuditSecurityListener        # Catches login/logout events
├── AuditRunListener             # Catches build start/complete events
├── AuditItemListener            # Catches job create/update/delete
├── AuditSaveableListener        # Catches configuration changes
├── AuditSessionListener         # Tracks user sessions
└── AuditRequestCapture          # Captures source IPs and user agents

Smart Features:
├── AnomalyDetector              # Detects unusual patterns
├── AuditAlertEngine             # Triggers alerts on risky events
├── AuditMetricsEngine           # Collects stats for dashboards
├── DataMasker                   # Hides sensitive data
└── LogRotationService           # Automatically cleans old logs

User Interface:
├── AuditLoggerManagementLink    # The dashboard UI
└── AuditLogEntrySerializer      # Formats logs for display/export
```

**Each component is designed to:**
- Run independently without blocking builds
- Use minimal memory and CPU
- Be easily testable and maintainable

## Compatibility & Requirements

**Works with:**
- **Jenkins:** 2.361.4 or later (tested & verified on up to 2.541.3)
- **Java:** 11 or later
- **Operating System:** Linux, macOS, Windows, or any OS that runs Jenkins
- **Deployment:** Standalone Jenkins, Docker, Kubernetes, cloud-hosted Jenkins

**What it works best with:**
- Any Jenkins pipeline or freestyle job
- Any authentication method (LDAP, SSO, native Jenkins, OAuth, etc.)
- Any Jenkins configuration (single agent or distributed)

## License

This project is licensed under a Commercial License. See [LICENSE.txt](LICENSE.txt) for details.

---

## Need Help?

- **Found a bug?** Report it on [GitHub Issues](https://github.com/harryofficial/AuditFlow/issues)
- **Have a feature request?** Open an issue and describe what you need
- **Source code:** [GitHub Repository](https://github.com/harryofficial/AuditFlow)

---

## What's New

### Version 1.0.0 (Current)
- Initial public release
- Comprehensive audit logging for all Jenkins events
- Paginated dashboard with filtering and search
- REST API for programmatic access
- Automatic log rotation and retention
- Data masking for sensitive information

### Version 1.1.0
- Verified against Jenkins 2.440
- Fixed timestamp handling after restarts
- Fixed credential mutation detection
- Fixed plugin manager routing for modern Jenkins versions
- Moved anomaly detection off the critical path for better performance

### Version 1.0.0
- Initial public release
