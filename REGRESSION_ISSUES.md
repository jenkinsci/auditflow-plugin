# Regression Issues

This file is the release gate for known audit regressions. Review it before every build and mark each scenario as verified against the current artifact.

## Last Verified Build

- Artifact: `target/auditflow-<version>.hpi`
- Validation timestamp: 2026-05-06/2026-05-07
- Repo gate: `verify` passed, including SpotBugs
- Live controller: Jenkins 2.541.3 in `jenkins-plugin-dev`

## Build Gate

1. From the repository root, run `java -classpath ".mvn\wrapper\maven-wrapper.jar" "-Dmaven.multiModuleProjectDirectory=." org.apache.maven.wrapper.MavenWrapperMain verify`.
2. Run the live Jenkins regression pass for credentials, plugin changes, build success/failure/abort, and critical authentication events.
3. Compare the observed results with the expectations below before shipping a build.

## Open Regression Risks

| ID | Risk | Failure Signature | Required Guard | Current Status |
| --- | --- | --- | --- | --- |
| REG-001 | Persisted events show startup/load time instead of original event time | Old audit rows reload with a fresh timestamp or wrong `readable` value after restart | `AuditLogStorageTimestampRegressionTest` must pass and live-reloaded entries must keep their original `timestampMs` and readable timestamp | Guard added |
| REG-002 | Servlet listener registration fails noisily on newer Jenkins cores | Startup logs show `UnsupportedOperationException`, `Failed to register Audit Session Listener`, or request capture never falls back | Startup log must show `PluginServletFilter fallback registered` without AuditFlow warning stack traces | Guard added |
| REG-003 | Credential mutations stop producing critical audit events | Missing `CREDENTIAL_CREATED`, `CREDENTIAL_UPDATED`, or `CREDENTIAL_DELETED` after credential store changes | Live regression must create, update, and delete one credential and confirm all three events | Must verify each build |
| REG-004 | Plugin manager actions stop producing plugin audit events | Missing `PLUGIN_DISABLED`, `PLUGIN_ENABLED`, `PLUGIN_REMOVED`, or `PLUGIN_INSTALLED` during plugin manager changes, especially on modern `/plugin/{name}/...` routes | Live regression must disable, enable, uninstall, and reinstall one plugin through plugin manager endpoints | Guard added, verify each build |
| REG-005 | Build outcome mapping logs the wrong terminal state | `BUILD_COMPLETED` logged for failures/aborts, or missing `BUILD_FAILED` / `BUILD_ABORTED` | Live regression must run one success build, one failure build, and one aborted build and confirm the exact outcome actions | Must verify each build |
| REG-006 | Critical authentication events disappear or lose actor/IP context | Missing `FAILED_LOGIN` / `LOGIN`, blank actor, or blank source IP during auth flow | Live regression must exercise failed and successful login and confirm action, username, and source IP | Must verify each build |
| REG-007 | Plugin manager progress/download pages generate false update events | Repeated `PLUGIN_UPDATED` rows for `plugin(s)` while the plugin manager progress page refreshes | Request classification must only treat real deploy/update endpoints as plugin updates, and live reinstall must stay free of repeated update spam | Guard added |

## Current Known Environment Noise

These are controller issues outside AuditFlow itself, but they can pollute startup logs during regression review:

| ID | Source | Impact on AuditFlow Validation |
| --- | --- | --- |
| ENV-001 | `run-tests.groovy` syntax error in `/var/jenkins_home/init.groovy.d` | Non-fatal startup noise; ignore unless startup never reaches `Jenkins is fully up and running` |
| ENV-002 | Greenballs reflective warning on Jenkins 2.541.3 / Java 17 | Plugin still loads; treat only as environment noise unless plugin manager actions fail |
| ENV-003 | `test-db-credential-job` load failure due credentials-binding mismatch | Existing job noise; use dedicated regression jobs instead of that job for build-path validation |

## Regression Checklist

- [x] Build passes with tests, packaging, and SpotBugs.
- [x] Persisted timestamps survive restart without shifting to startup time.
- [x] Failed login is logged with username and source IP.
- [x] Successful login is logged with username and source IP.
- [x] Credential create/update/delete each emit the expected audit action.
- [x] Plugin disable/enable/remove/reinstall each emit the expected audit action.
- [x] Plugin reinstall does not generate repeated false `PLUGIN_UPDATED` spam.
- [x] Success, failure, and abort builds each emit the expected terminal audit action.
- [x] No new AuditFlow startup warnings appear in Jenkins logs.