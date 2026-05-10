# Script Console & URL Matching Security Hardening

## Overview

This document explains the security vulnerabilities identified in the AuditFlow plugin's URL-matching approach and the comprehensive fixes implemented.

## Issues Addressed

### 1. Unreliable URL Pattern Matching

**Original Problem:**
The plugin relied on fragile string matching to detect security-critical operations:
```java
// VULNERABLE CODE
if ("/restart".equals(uri) || "/safeRestart".equals(uri)) { ... }  // Exact match only
if (uri.contains("/pluginManager/install")) { ... }                 // Easy to bypass with prefix
if (uri.endsWith("/disable")) { ... }                               // Easy to bypass with query params
```

**Vulnerabilities:**
- **Prefix bypass**: `/static/lol/restart` would bypass restart detection
- **Suffix bypass**: `/restart?foo=bar#section` might bypass exact match
- **Job name collisions**: A job named "restart" could trigger false positives
- **Path manipulation**: `/job/jobnamehere/parent/restart` bypasses length checks

**Solution: RouteAwareUrlMatcher**
- Normalizes URIs (strips query strings, fragments, context paths)
- Parses path into segments and validates structure
- Validates segment count and sequence
- Prevents prefix/suffix injection attacks
- Distinguishes between route keywords and user-provided names

### 2. Missing Script Console Detection

**Original Problem:**
The plugin had NO detection for script console access - one of the most critical security-sensitive Jenkins features.

Only found in `AuditSecurityListener`:
```java
// INCOMPLETE - Only classifies auth method, doesn't detect console access
if (path.contains("/scriptText") || path.contains("/script")) {
    return "api-token";  // Just auth method, not actual detection
}
```

**Vulnerabilities:**
- Script console access completely unaudited
- No reliable event capture

**Solution: AuditScriptListener**
- Implements Jenkins core `ScriptListener`
- Tracks script execution from the callback context instead of request URIs
- Keeps the stable `SCRIPT_CONSOLE_ACCESS` action for script console and `scriptText` execution
- Captures script preview, feature source, correlation id, and user context from the listener callback

### 3. Route-Unaware Matching

**Original Problem:**
Simple string matching doesn't account for Jenkins' flexible URL routing.

Examples of confusion:
```
/job/script/script → is this a job named "script" with an action?
/view/restart → is this accessing a view or restarting Jenkins?
/manage/pluginManager/plugin/myjob/script → complex nested structure
```

**Solution: RouteAwareUrlMatcher.isRestartAction()**
```java
// Route-aware: validates exact structure
// Valid:   /restart, /safeRestart, /manage/restart, /manage/safeRestart
// Invalid: /static/restart, /job/restart, /view/restart
if (segments.length == 2 && "restart".equals(segments[1])) {
    // Global restart - valid
}
if (segments.length == 3 && "manage".equals(segments[1]) && "restart".equals(segments[2])) {
    // Manage page restart - valid
}
// All other paths rejected
```

## Implementation Details

### New Classes

#### 1. `RouteAwareUrlMatcher.java`
Provides route-aware URL matching functions:
- `isRestartAction(uri)` - Detects global and manage-page restarts only
- `isPluginManagerAction(uri)` - Validates plugin manager access
- `isConfigurationChange(uri)` - Detects config endpoints
- `extractPluginName(uri)` - Extracts plugin name from URI
- `normalizeUri(uri)` - Cleans up URI for processing

#### 2. `AuditScriptListener.java`
Provides event-based script execution tracking via Jenkins core `ScriptListener`:
- `onScriptExecution(...)` - Logs script execution directly from the callback context
- `onScriptOutput(...)` - Intentionally ignored to avoid duplicate audit rows

### Modified Classes

#### `AuditRequestCapture.java`
- Updated `detectAdminAction()` to use `RouteAwareUrlMatcher`
- Enhanced plugin action classification
- Removed script console request matching so script auditing only happens at execution time

## Security Improvements

### Before
```
Restart detection: /restart, /manage/restart only
Script detection: NONE
Plugin detection: Any path with "/pluginManager/"
Bypass examples:
  - /static/anything/restart (bypasses)
  - /job/script/anything (false positive)
  - /my-app/restart (bypasses)
```

### After
```
Restart detection: Route-validated, exact segment matching
  - Prevents: /static/lol/restart
  - Prevents: /job/restart
  - Prevents: /view/restart
  - Validates: /restart, /manage/restart only

Script detection: Listener-driven from Jenkins core
  - Captures: script console and `scriptText` execution via `ScriptListener`
  - Avoids: false positives from route heuristics
  - Integrates with callback context rather than request URIs

Plugin detection: Route-validated at manager root level
  - Prevents: /job/plugins/... (job named "plugins")
  - Ensures: /pluginManager only at root
```

## Remaining Limitations

⚠️ **Important**: This audit plugin has fundamental limitations due to its non-intrusive design:

### 1. URL Matching vs. Method Interception
Even with route-aware matching, the plugin matches HTTP URLs, not actual Jenkins method calls.

**Scenario**: A custom Jenkins plugin could expose the same functionality via a different URL without this plugin knowing about it.

**Example**:
```
/jenkins/restart → Detected
/jenkins/api/system/restart → May not be detected if custom endpoint
/jenkins/internal/doRestart → May not be detected
```

**Mitigation**: Use Jenkins event system where possible. For methods with no dedicated events, URL matching + comprehensive testing is the best option.

### 2. Script Interception Scope
The current implementation now uses Jenkins core `ScriptListener`, so it captures real script execution callbacks rather than HTTP path guesses.

**What we capture**: Script console and `scriptText` execution, plus other Groovy execution paths exposed through `ScriptListener`
**What we don't capture yet**: Script approval and rejection events from the script-security plugin

**Future approach**: Add a separate approval listener only when a real script-security extension point is wired.

### 3. Complex Parameter Extraction
Script details now come from the `ScriptListener` callback, but coverage still depends on which execution paths fire that extension point.

**What we capture**: The script text exposed by the callback and listener metadata such as feature and correlation id
**What we don't capture**: Approval decisions and execution paths that do not fire Jenkins core `ScriptListener`

### 4. Jenkins Version Compatibility
These changes are tested on Jenkins 2.361.4. Behavior may vary on:
- Older versions with different URL patterns
- Newer versions with experimental features
- Custom builds with security overrides

## Testing Recommendations

### Unit Tests (Added)
- `RouteAwareUrlMatcher` test suite covering:
  - Valid restart patterns: `/restart`, `/manage/restart`, `/manage/safeRestart`
  - Invalid patterns: `/static/restart`, `/job/restart`, `/view/restart`
  - Plugin manager: root-level `/pluginManager/plugin/...` only

- `AuditScriptListenerTest` covering:
  - Real `POST /scriptText` execution through Jenkins test harness
  - Audit entry emission with the stable `SCRIPT_CONSOLE_ACCESS` action

### Integration Tests (Manual)
1. **Restart Detection**
   - Issue restart via UI → Audit log entry created
   - Issue restart via API → Audit log entry created
   - Attempt prefix injection → Not detected (good)

2. **Script Console Access**
  - Execute `POST /scriptText` with a valid crumb → Audit entry: `SCRIPT_CONSOLE_ACCESS`
  - Execute from script console UI → Audit entry with script preview and listener metadata

3. **Plugin Operations**
   - Install plugin → `PLUGIN_INSTALLED`
   - Uninstall plugin → `PLUGIN_REMOVED`
   - Enable/disable plugin → `PLUGIN_ENABLED`/`PLUGIN_DISABLED`

## Migration Notes

### For Plugin Operators
- No configuration changes required
- Script console access now automatically audited
- Review audit logs for new `SCRIPT_CONSOLE_ACCESS` entries

### For Security Officers
- Add script console events to compliance monitoring
- Review existing logs - script console access was undetected before
- Treat approval/rejection auditing as unsupported until a real script-security hook is added

## Future Improvements

### Phase 2: Event-Based Detection
- Implement proper Jenkins listener interfaces for:
  - Script approval events from script-security (when available)
  - Restart completion events
  - Plugin state change events

### Phase 3: Deep Method Hooking
- Use reflection/bytecode manipulation to intercept:
  - Actual method calls (not just HTTP requests)
  - Script execution with parameters
  - Plugin class loading

### Phase 4: Jenkins Core Integration
- Contribute patches to Jenkins to expose security events
- Use proper SPI/extension points if available
- Coordinate with security.security.* packages

## References

- [Jenkins Security Documentation](https://www.jenkins.io/security/)
- [Jenkins Script Approval](https://www.jenkins.io/doc/book/managing/script-approval/)
- [Jenkins Extension Points](https://www.jenkins.io/doc/developer/extensions/)
- Original GitHub Issues:
  - URL matching bypass concern
  - Missing script console detection
  - False positives in URL matching
