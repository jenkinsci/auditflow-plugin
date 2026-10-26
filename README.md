# AuditFlow – Jenkins Audit Logging & Anomaly Detection

[![Jenkins Plugin](https://img.shields.io/badge/Jenkins%20Plugin-AuditFlow-blue.svg)](https://plugins.jenkins.io/auditflow)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://www.oracle.com/java/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**AuditFlow** provides non-blocking enterprise audit logging, real-time security anomaly detection, and multi-channel webhook alerting for Jenkins controllers. Capture authentications, build runs, configuration edits, credential operations, node lifecycles, CLI executions, and script console evaluations in a queryable dashboard with zero build overhead.

---

## Key Features

- **Non-Blocking Architecture**: Asynchronous ring buffer and batch writer with `<0.1%` build impact.
- **Interactive Dashboard**: Search, filter, inspect, and paginate audit events (`/auditflow-logs`) with CSV/JSON exports.
- **Proactive Anomaly Detection**: Real-time heuristics flagging Brute Force attacks, Multi-IP Logins, Unusual IP sources, Privilege Escalation, and User Lifecycle bursts.
- **Smart Webhook Routing**: Asynchronous alert dispatching to Slack, Microsoft Teams, or custom endpoints with channel routing, minimum severity thresholds, and action filters.
- **Direct Critical Log Escalation**: Instant webhook alerts for high-risk operations (e.g. `SCRIPT_CONSOLE_ACCESS`, credential modifications).
- **Enterprise Privacy & Retention**: Automated log rotation, formula-injection protected exports, and automated masking of secrets, API tokens, emails, and credit cards.
- **REST API**: Full programmatic access to audit logs, real-time system metrics, and alert management.

---

## Dashboard & Visuals

| Audit Dashboard | Insights & Anomalies |
|:---:|:---:|
| ![Main Dashboard](src/screenshots/01-main-dashboard.png) | ![Insights Panel](src/screenshots/02-insights-panel.png) |

---

## Event Coverage & Severity

AuditFlow automatically captures and categorizes controller events:

| Category | Actions Tracked | Default Severity |
|:---|:---|:---:|
| **Authentication** | `LOGIN`, `LOGOUT`, `FAILED_LOGIN`, `API_AUTH`, `SSO_LOGIN` | `CRITICAL` / `MEDIUM` |
| **Scripts & Console** | `SCRIPT_CONSOLE_ACCESS`, `SCRIPT_EXECUTION` | `CRITICAL` |
| **Credentials** | `CREDENTIAL_CREATED`, `CREDENTIAL_ACCESSED`, `CREDENTIAL_UPDATED`, `CREDENTIAL_DELETED` | `HIGH` / `LOW` |
| **System & Security** | `USER_CONFIG_UPDATED`, `SECURITY_REALM_CHANGED`, `SYSTEM_RESTART` | `HIGH` / `MEDIUM` |
| **Jobs & Pipelines** | `JOB_CREATED`, `JOB_UPDATED`, `JOB_DELETED`, `JOB_RENAMED`, `JOB_COPIED` | `HIGH` / `LOW` |
| **Nodes & Agents** | `NODE_CREATED`, `NODE_UPDATED`, `NODE_DELETED`, `NODE_ONLINE`, `NODE_OFFLINE` | `MEDIUM` / `LOW` |
| **Builds** | `BUILD_STARTED`, `BUILD_COMPLETED`, `BUILD_DELETED` | `LOW` |
| **CLI** | `CLI_EXECUTION` | `INFO` |

---

## Webhook Routing & Alerting

Configure webhook notifications via **Manage Jenkins** → **System** → **Alert Notifications & Webhooks**:

- **Unified Webhook Destinations**: Add one or more destination channels (Slack, Microsoft Teams, or custom endpoints) with fine-grained routing:
  - **Scope**: Route all alerts, anomalies only, or direct critical audit logs only.
  - **Min Severity**: Filter by `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `ALL`.
  - **Event Categories**: Target functional areas (*Authentication*, *System & Security Config*, *Credentials*, *Jobs & Builds*, *Nodes & Agents*, *Security Anomalies*).
  - **Action Filter**: Comma-separated action names for specific matching (e.g. `SCRIPT_CONSOLE_ACCESS, SYSTEM_RESTART`).
  - **Rich Payloads**: Formatted Slack attachments with severity color bars, direct links to `/manage/auditflow-logs/`, and Microsoft Teams compatibility.
  - **Test Endpoint**: Dedicated test button per destination for instant connectivity checks.

---

## Anomaly Detection Heuristics

AuditFlow evaluates events in real time against configurable risk models:

1. **Brute Force Protection**: Rapid repeated authentication failures from an account or IP.
2. **Concurrent Multi-IP Logins**: Same user authenticated concurrently from distinct network locations.
3. **Unusual IP Access**: Logins originating from new or uncharacteristic IP subnets.
4. **Privilege Escalation**: Unauthorized role promotions or administrative rights changes.
5. **User Lifecycle Burst**: Rapid creation, modification, or mass deletion of user accounts.

Active alerts appear on the dashboard with one-click dismissal and automated escalation.

---

## REST API Reference

Query audit records programmatically:

```bash
# Query audit logs by user and action
curl -u admin:token \
  "http://localhost:8080/auditflow/api/logs?user=john&action=LOGIN&limit=50"
```

### Sample Response

```json
{
  "status": "success",
  "count": 1,
  "logs": [
    {
      "timestamp": "2026-10-24T14:09:30Z",
      "timestampMs": 1792850970000,
      "user": "john",
      "action": "LOGIN",
      "target": "Jenkins",
      "details": "User authenticated from 192.168.1.100",
      "severity": "LOW",
      "sourceIp": "192.168.1.100",
      "authMethod": "form"
    }
  ]
}
```

Additional endpoints:
- `GET /auditflow/api/stats` — Real-time event and security counter metrics.
- `GET /auditflow-logs/alerts` — Active anomaly alerts.
- `POST /auditflow-logs/dismissAlert?id=<alertId>` — Dismiss a security alert.

---

## Storage & Performance

- **Storage Location**: `$JENKINS_HOME/auditflow-logs/audit.jsonl` (JSON Lines format).
- **Buffer**: 10,000-entry in-memory ring buffer with non-blocking async batch flushing.
- **Log Retention**: Configurable retention days and max log file size with automatic rotation.
- **SIEM Forwarding**: Easily ingested by Splunk (HEC), AWS CloudWatch, Datadog, ELK Stack, or Fluentd forwarders.

---

## Quickstart Configuration

Navigate to **Manage Jenkins** → **System** → **AuditFlow Configuration**:
1. Check event categories to record under **Event Logging Controls**.
2. Configure **Security Anomaly Detection** heuristics.
3. Under **Alert Notifications & Webhooks**, add **Webhook Destinations** and test connectivity with the **Test Endpoint** button.
4. Access the live log viewer anytime at **Manage Jenkins** → **AuditFlow Logs**.

---

## License & Support

- **License**: [MIT](LICENSE)
- **Issues**: Report bugs or feature requests on [GitHub Issues](https://github.com/jenkinsci/auditflow-plugin/issues).
