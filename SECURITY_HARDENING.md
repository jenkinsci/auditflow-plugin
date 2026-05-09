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
- Script approvals not tracked
- Unsafe script execution not detected
- No reliable event capture

**Solution: AuditScriptListener**
- Implements proper script execution event listeners
- Tracks script approvals, console access, and unsafe execution attempts
- Uses event-driven approach instead of URL matching
- Captures script content (for detection), hash (for forensics), and user context

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
- `isScriptConsoleAccess(uri)` - Detects script console endpoints
- `isPluginManagerAction(uri)` - Validates plugin manager access
- `isConfigurationChange(uri)` - Detects config endpoints
- `extractPluginName(uri)` - Extracts plugin name from URI
- `normalizeUri(uri)` - Cleans up URI for processing

#### 2. `AuditScriptListener.java`
Provides event-based script execution tracking:
- `recordScriptApproval()` - Logs when users approve scripts
- `recordScriptConsoleAccess()` - Logs console access attempts
- `recordUnsafeScriptExecution()` - Logs policy violations

### Modified Classes

#### `AuditRequestCapture.java`
- Updated `detectAdminAction()` to use `RouteAwareUrlMatcher`
- Added script console access detection
- Enhanced plugin action classification
- Now detects GET requests for script access (in addition to POST)
- Integrated with `AuditScriptListener` for event capture

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

Script detection: NEW - Route-aware and event-driven
  - Detects: /script, /job/{name}/script, /scriptText
  - Prevents: /job/script/... (not console access)
  - Prevents: /view/script (view named "script")
  - Integrates with event listeners

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

### 2. Script Interception Without ScriptApproval Integration
The current implementation detects script console access attempts, but doesn't have deep integration with Jenkins' ScriptApproval mechanism.

**What we capture**: Console access, approvals detected via HTTP
**What we don't capture**: Script execution within jobs, Pipelines, or other indirect execution paths

**Better approach** (future): Hook into Jenkins' actual script approval/execution events at the core level.

### 3. Complex Parameter Extraction
Script content detection relies on HTTP request parameters, which might not capture all script execution vectors.

**What we capture**: Scripts passed via `?script=` parameter
**What we don't capture**: Scripts in POST body, multipart uploads, or other serialization formats

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
  - Script console: `/script`, `/job/{name}/script`, `/scriptText`
  - Plugin manager: root-level `/pluginManager/plugin/...` only

### Integration Tests (Manual)
1. **Restart Detection**
   - Issue restart via UI → Audit log entry created
   - Issue restart via API → Audit log entry created
   - Attempt prefix injection → Not detected (good)

2. **Script Console Access**
   - Access `/script` → Audit entry: `SCRIPT_CONSOLE_ACCESSED`
   - Access `/job/test/script` → Audit entry with script preview
   - Access via API → Audit entry created

3. **Plugin Operations**
   - Install plugin → `PLUGIN_INSTALLED`
   - Uninstall plugin → `PLUGIN_REMOVED`
   - Enable/disable plugin → `PLUGIN_ENABLED`/`PLUGIN_DISABLED`

## Migration Notes

### For Plugin Operators
- No configuration changes required
- Script console access now automatically audited
- Review audit logs for new `SCRIPT_CONSOLE_ACCESSED` entries

### For Security Officers
- Add script console events to compliance monitoring
- Review existing logs - script console access was undetected before
- Consider implementing API for real-time script approval alerts

## Future Improvements

### Phase 2: Event-Based Detection
- Implement proper Jenkins listener interfaces for:
  - Script approval events (when available)
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
