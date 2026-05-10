package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.BuildableItemWithBuildWrappers;
import hudson.model.Cause;
import hudson.model.Job;
import hudson.model.ParameterValue;
import hudson.model.ParametersAction;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.listeners.RunListener;
import hudson.plugins.git.GitSCM;
import hudson.plugins.git.UserRemoteConfig;
import hudson.scm.SCM;
import hudson.tasks.BuildWrapper;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.SecretBuildWrapper;
import org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition;
import org.jenkinsci.plugins.workflow.flow.FlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Build lifecycle event listener.
 * Captures trigger chain (who, how), parameters, and results.
 * Detects bulk "purge build history" via rapid-fire onDeleted calls.
 */
@Extension
public class AuditRunListener extends RunListener<Run<?, ?>> {
    private static final Logger LOGGER = Logger.getLogger(AuditRunListener.class.getName());

    /** Track rapid-fire build deletions per job to detect purge operations. */
    private static final long PURGE_WINDOW_MS = 2000; // 2 second window
    private static final int PURGE_THRESHOLD = 3;     // >= 3 deletes in window = purge
    private final ConcurrentHashMap<String, PurgeTracker> purgeTrackers = new ConcurrentHashMap<>();

    /** Shared scheduler for purge flush — avoids creating a raw Thread per delete event. */
    private static final ScheduledExecutorService PURGE_SCHEDULER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "AuditFlow-PurgeFlush");
        t.setDaemon(true);
        return t;
    });

    private static class PurgeTracker {
        final String user;
        final String jobName;
        final long firstDelete;
        int count;
        int minBuild = Integer.MAX_VALUE;
        int maxBuild = Integer.MIN_VALUE;
        /** Track actual deleted build numbers to avoid logging phantom builds. */
        final Set<Integer> deletedBuilds = ConcurrentHashMap.newKeySet();
        boolean purgeLogged;

        PurgeTracker(String user, String jobName, long time) {
            this.user = user;
            this.jobName = jobName;
            this.firstDelete = time;
        }

        void addBuild(int buildNum) {
            count++;
            deletedBuilds.add(buildNum);
            minBuild = Math.min(minBuild, buildNum);
            maxBuild = Math.max(maxBuild, buildNum);
        }

        boolean isExpired(long now) {
            return (now - firstDelete) > PURGE_WINDOW_MS;
        }
    }

    @Override
    public void onStarted(Run<?, ?> run, TaskListener listener) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableBuildEvents()) return;

            String jobName = run.getParent().getFullName();
            int buildNum = run.getNumber();
            String user = "SYSTEM";
            String triggerType = "unknown";
            List<String> triggerDetails = new ArrayList<>();

            for (Cause cause : run.getCauses()) {
                String[] parsed = parseCause(cause);
                if (!"SYSTEM".equals(parsed[0])) user = parsed[0];
                triggerType = parsed[1];
                triggerDetails.add(parsed[2]);
            }

            String params = extractParameters(run);
            String details = String.format("Build #%d started | Trigger: %s | Causes: [%s]%s",
                    buildNum, triggerType,
                    String.join("; ", triggerDetails),
                    params.isEmpty() ? "" : " | Params: " + params);

            AuditLogEntry entry = AuditLogEntry.withTrigger(user, "BUILD_STARTED", jobName, details, triggerType);

            // Capture source IP from RemoteCause (remote API triggers)
            for (Cause cause : run.getCauses()) {
                if (cause instanceof Cause.RemoteCause) {
                    entry.setSourceIp(((Cause.RemoteCause) cause).getAddr());
                    break;
                }
            }

            AuditLogStorage.getInstance().addEntry(entry);

            // Log SCM credential usage at build START — these are known from job config
            // and represent the actual moment the credential will be checked out.
            logScmCredentialUsage(run, jobName, user);

            // Log runtime-bound credentials (SecretBuildWrapper / withCredentials) at BUILD START.
            // These are known from job config wrappers and should be logged BEFORE the build runs.
            logRuntimeCredentialUsage(run, jobName, user);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error recording build start", e);
        }
    }

    @Override
    public void onCompleted(Run<?, ?> run, TaskListener listener) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableBuildEvents()) return;

            String jobName = run.getParent().getFullName();
            int buildNum = run.getNumber();
            hudson.model.Result buildResult = run.getResult();
            String result = buildResult != null ? buildResult.toString() : "UNKNOWN";
            long duration = System.currentTimeMillis() - run.getStartTimeInMillis();
            String user = extractTriggerUser(run);

            String details = String.format("Build #%d completed: %s (duration: %s) | Triggered by %s",
                    buildNum, result, formatDuration(duration), user);

            AuditLogEntry entry = AuditLogEntry.withTrigger(user, "BUILD_COMPLETED", jobName, details,
                    extractTriggerType(run));

            // Capture source IP from RemoteCause (remote API triggers)
            for (Cause cause : run.getCauses()) {
                if (cause instanceof Cause.RemoteCause) {
                    entry.setSourceIp(((Cause.RemoteCause) cause).getAddr());
                    break;
                }
            }

            // For FAILURE/ABORTED, log only the specific event (not BUILD_COMPLETED)
            if ("FAILURE".equals(result)) {
                AuditLogEntry failEntry = AuditLogEntry.withTrigger(user, "BUILD_FAILED", jobName,
                        String.format("Build #%d FAILED (duration: %s) | Triggered by %s", buildNum, formatDuration(duration), user),
                        extractTriggerType(run));
                failEntry.setSeverity("HIGH");
                for (Cause cause : run.getCauses()) {
                    if (cause instanceof Cause.RemoteCause) {
                        failEntry.setSourceIp(((Cause.RemoteCause) cause).getAddr());
                        break;
                    }
                }
                AuditLogStorage.getInstance().addEntry(failEntry);
            } else if ("ABORTED".equals(result)) {
                AuditLogEntry abortEntry = AuditLogEntry.withTrigger(user, "BUILD_ABORTED", jobName,
                        String.format("Build #%d ABORTED (duration: %s) | Triggered by %s", buildNum, formatDuration(duration), user),
                        extractTriggerType(run));
                abortEntry.setSeverity("HIGH");
                for (Cause cause : run.getCauses()) {
                    if (cause instanceof Cause.RemoteCause) {
                        abortEntry.setSourceIp(((Cause.RemoteCause) cause).getAddr());
                        break;
                    }
                }
                AuditLogStorage.getInstance().addEntry(abortEntry);
            } else {
                AuditLogStorage.getInstance().addEntry(entry);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error recording build completion", e);
        }
    }

    @Override
    public void onDeleted(Run<?, ?> run) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config != null && !config.isEnableBuildEvents()) return;

            String jobName = run.getParent().getFullName();
            int buildNum = run.getNumber();
            String user = currentUser();

            // Suppress SYSTEM-initiated build deletions (build rotation) — not audit-relevant
            if ("SYSTEM".equals(user)) return;

            long now = System.currentTimeMillis();
            String key = user + "|" + jobName;

            // Check for expired trackers first
            PurgeTracker tracker = purgeTrackers.get(key);
            if (tracker != null && tracker.isExpired(now)) {
                flushPurgeTracker(tracker);
                purgeTrackers.remove(key);
                tracker = null;
            }

            if (tracker == null) {
                tracker = new PurgeTracker(user, jobName, now);
                purgeTrackers.put(key, tracker);
            }
            tracker.addBuild(buildNum);

            // If we've hit the purge threshold, log a BUILDS_PURGED event
            if (tracker.count >= PURGE_THRESHOLD && !tracker.purgeLogged) {
                tracker.purgeLogged = true;
                AuditLogEntry entry = new AuditLogEntry(user, "BUILDS_PURGED", jobName,
                        String.format("Build history purged: %d+ builds (#%d - #%d) deleted by %s",
                                tracker.count, tracker.minBuild, tracker.maxBuild, user));
                AuditLogStorage.getInstance().addEntry(entry);
                LOGGER.log(Level.INFO, "BUILDS_PURGED: job={0} count={1} by user={2}",
                        new Object[]{jobName, tracker.count, user});
            } else if (tracker.count < PURGE_THRESHOLD) {
                // Below threshold — log individual delete (may be upgraded to purge later)
                // Schedule a flush to emit individual deletes if threshold not reached
                scheduleFlush(key, now);
            } else {
                // Already logged purge, update count
                LOGGER.log(Level.FINE, "Build #{0} added to purge batch for {1} (count={2})",
                        new Object[]{buildNum, jobName, tracker.count});
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error recording build deletion", e);
        }
    }

    private void scheduleFlush(String key, long startTime) {
        // Use shared scheduler instead of creating a new thread per delete
        PURGE_SCHEDULER.schedule(() -> {
            PurgeTracker tracker = purgeTrackers.remove(key);
            if (tracker != null && !tracker.purgeLogged) {
                flushPurgeTracker(tracker);
            }
        }, PURGE_WINDOW_MS + 200, java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    private void flushPurgeTracker(PurgeTracker tracker) {
        if (tracker.purgeLogged) return;
        // Below threshold — log individual BUILD_DELETED events for actual deleted builds
        for (int b : tracker.deletedBuilds) {
            AuditLogStorage.getInstance().addEntry(
                    new AuditLogEntry(tracker.user, "BUILD_DELETED", tracker.jobName,
                            String.format("Build #%d deleted by %s", b, tracker.user)));
        }
    }

    /**
     * Log SCM credential usage at BUILD START (before checkout).
     * SCM credentials are defined in job config, so they're known before the build runs.
     * This captures the actual moment the credential will be used for checkout.
     */
    private void logScmCredentialUsage(Run<?, ?> run, String jobName, String user) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null || !config.isEnableCredentialEvents()) return;

            Set<String> credentialIds = new LinkedHashSet<>();
            extractScmCredentials(run, credentialIds);

            for (String credId : credentialIds) {
                String details = String.format("Credential '%s' bound for SCM checkout in job '%s' (Build #%d, triggered by %s)",
                        credId, jobName, run.getNumber(), user);
                AuditLogEntry entry = new AuditLogEntry(user, "CREDENTIAL_ACCESSED",
                        "Credentials/" + credId, details);
                entry.setSeverity("HIGH");
                AuditLogStorage.getInstance().addEntry(entry);
                LOGGER.log(Level.FINE, "CREDENTIAL_ACCESSED (SCM, build start): cred={0} job={1} build=#{2}",
                        new Object[]{credId, jobName, run.getNumber()});
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error checking SCM credential usage for {0}: {1}",
                    new Object[]{run.getFullDisplayName(), e.getMessage()});
        }
    }

    /**
     * Log runtime-bound credentials (SecretBuildWrapper / withCredentials) at BUILD START.
     * Credentials are discovered from job config wrappers and build actions.
     * Excludes SCM credentials already logged at start.
     */
    private void logRuntimeCredentialUsage(Run<?, ?> run, String jobName, String user) {
        try {
            AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
            if (config == null || !config.isEnableCredentialEvents()) return;

            // Collect SCM creds to exclude (already logged at start)
            Set<String> scmCreds = new LinkedHashSet<>();
            extractScmCredentials(run, scmCreds);

            // Collect runtime creds from two sources:
            // 1. Build actions (for pipeline jobs using withCredentials step)
            // 2. Build wrappers from job config (for freestyle jobs using SecretBuildWrapper)
            Set<String> runtimeCreds = new LinkedHashSet<>();
            
            // 1. Extract from build actions
            for (Object action : run.getAllActions()) {
                extractCredentialIdsFromAction(action, runtimeCreds);
            }

            // 2. Extract from job configuration (build wrappers like SecretBuildWrapper)
            extractCredentialsFromJobWrappers(run, runtimeCreds);

            // Also check build parameters for credential parameter values
            extractCredentialParameters(run, runtimeCreds);

            // Only log creds NOT already covered by SCM
            runtimeCreds.removeAll(scmCreds);

            for (String credId : runtimeCreds) {
                String details = String.format("Credential '%s' used at runtime by job '%s' (Build #%d, triggered by %s)",
                        credId, jobName, run.getNumber(), user);
                AuditLogEntry entry = new AuditLogEntry(user, "CREDENTIAL_ACCESSED",
                        "Credentials/" + credId, details);
                entry.setSeverity("HIGH");
                AuditLogStorage.getInstance().addEntry(entry);
                LOGGER.log(Level.FINE, "CREDENTIAL_ACCESSED (runtime): cred={0} job={1} build=#{2}",
                        new Object[]{credId, jobName, run.getNumber()});
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error checking runtime credential usage for {0}: {1}",
                    new Object[]{run.getFullDisplayName(), e.getMessage()});
        }
    }

    /**
     * Extract credentials from build wrappers configured on the job.
     * For example, SecretBuildWrapper from credentials-binding plugin with UsernamePasswordMultiBinding.
     * Build wrappers are stored in the Job config, not on the Build object.
     */
    private void extractCredentialsFromJobWrappers(Run<?, ?> run, Set<String> ids) {
        try {
            Job<?, ?> job = run.getParent();
            if (!(job instanceof BuildableItemWithBuildWrappers buildableJob)) {
                return;
            }

            for (BuildWrapper wrapper : buildableJob.getBuildWrappersList()) {
                if (wrapper instanceof SecretBuildWrapper secretBuildWrapper) {
                    for (MultiBinding<?> binding : secretBuildWrapper.getBindings()) {
                        String credId = binding.getCredentialsId();
                        if (credId != null && !credId.isEmpty()) {
                            ids.add(credId);
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error extracting credentials from job wrappers: {0}", e.getMessage());
        }
    }

    /**
     * Extract credential IDs passed as build parameters (CredentialsParameterValue).
     */
    private void extractCredentialParameters(Run<?, ?> run, Set<String> ids) {
        try {
            ParametersAction pa = run.getAction(ParametersAction.class);
            if (pa == null) return;
            for (ParameterValue pv : pa.getParameters()) {
                String className = pv.getClass().getName().toLowerCase();
                if (className.contains("credential")) {
                    Object val = pv.getValue();
                    if (val instanceof String && !((String) val).isEmpty()) {
                        ids.add((String) val);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Error extracting credential parameters", e);
        }
    }

    /**
     * Extract credential IDs from the Job's SCM configuration via reflection.
     * Handles: GitSCM → getUserRemoteConfigs() → getCredentialsId()
     * Also handles: CpsScmFlowDefinition → getScm() for pipeline jobs.
     */
    private void extractScmCredentials(Run<?, ?> run, Set<String> ids) {
        try {
            Job<?, ?> job = run.getParent();

            if (job instanceof AbstractProject<?, ?> project) {
                extractCredentialIdsFromScm(project.getScm(), ids);
                return;
            }

            if (job instanceof WorkflowJob workflowJob) {
                FlowDefinition definition = workflowJob.getDefinition();
                if (definition instanceof CpsScmFlowDefinition cpsScmFlowDefinition) {
                    extractCredentialIdsFromScm(cpsScmFlowDefinition.getScm(), ids);
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINEST, "Could not extract SCM credentials", e);
        }
    }

    /**
     * Extract credential IDs from an SCM object (GitSCM, SubversionSCM, etc.) via reflection.
     */
    private void extractCredentialIdsFromScm(SCM scm, Set<String> ids) {
        if (scm == null) {
            return;
        }

        try {
            if (scm instanceof GitSCM gitScm) {
                for (UserRemoteConfig config : gitScm.getUserRemoteConfigs()) {
                    String credId = config.getCredentialsId();
                    if (credId != null && !credId.isEmpty()) {
                        ids.add(credId);
                    }
                }
                return;
            }

            // Generic: try getCredentialsId() directly on the SCM
            String credId = invokeStringGetter(scm, "getCredentialsId");
            if (credId != null && !credId.isEmpty()) {
                ids.add(credId);
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINEST, "Could not extract SCM credential IDs", e);
        }
    }

    private static String invokeStringGetter(Object obj, String methodName) {
        try {
            Method m = obj.getClass().getMethod(methodName);
            Object result = m.invoke(obj);
            return result instanceof String ? (String) result : null;
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            return null;
        }
    }

    /**
     * Extract credential IDs from a build action via reflection.
     * Handles multiple plugin patterns:
     *   - getCredentialId() / getCredentialsId() returning a single String
     *   - getCredentialIds() / getCredentials() returning Collection or Map
     *   - getBindings() returning list of binding objects (credentials-binding plugin)
     *   - CredentialsParameterBinder from org.jenkinsci.plugins.credentialsbinding
     */
    private void extractCredentialIdsFromAction(Object action, Set<String> ids) {
        try {
            String actionClass = action.getClass().getName();

            // Special handling for CredentialsParameterBinder
            if (actionClass.contains("CredentialsParameterBinder")) {
                try {
                    Method getBindingsMethod = action.getClass().getMethod("getBindings");
                    Object bindingsResult = getBindingsMethod.invoke(action);
                    if (bindingsResult instanceof Iterable) {
                        for (Object binding : (Iterable<?>) bindingsResult) {
                            String id = invokeStringGetter(binding, "getCredentialsId");
                            if (id == null) id = invokeStringGetter(binding, "getCredentialId");
                            if (id != null && !id.isEmpty()) ids.add(id);
                        }
                    }
                } catch (NoSuchMethodException ignored) {}
            }

            // Special handling for TrackingAction from credentials-binding
            if (actionClass.contains("TrackingAction")) {
                for (Method m : action.getClass().getMethods()) {
                    if (m.getParameterCount() != 0) continue;
                    if ("getCredentials".equals(m.getName())) {
                        try {
                            Object result = m.invoke(action);
                            if (result instanceof Map) {
                                for (Object value : ((Map<?, ?>) result).values()) {
                                    if (value instanceof Iterable) {
                                        for (Object item : (Iterable<?>) value) {
                                            extractCredentialIdFromObject(item, ids);
                                        }
                                    }
                                }
                            } else if (result instanceof Iterable) {
                                for (Object item : (Iterable<?>) result) {
                                    extractCredentialIdFromObject(item, ids);
                                }
                            }
                        } catch (Exception ex) {
                            LOGGER.log(Level.FINE, "TrackingAction.getCredentials() failed: {0}", ex.getMessage());
                        }
                    }
                }
            }

            // Generic extraction for all action classes
            for (Method m : action.getClass().getMethods()) {
                String name = m.getName();
                if (m.getParameterCount() != 0) continue;
                if (m.getDeclaringClass() == Object.class) continue;

                if ("getCredentialId".equals(name) || "getCredentialsId".equals(name)) {
                    Object result = m.invoke(action);
                    if (result instanceof String && !((String) result).isEmpty()) {
                        ids.add((String) result);
                    }
                } else if ("getCredentialIds".equals(name) || "getCredentials".equals(name)) {
                    Object result = m.invoke(action);
                    if (result instanceof Map) {
                        for (Object value : ((Map<?, ?>) result).values()) {
                            if (value instanceof Iterable) {
                                for (Object item : (Iterable<?>) value) {
                                    extractCredentialIdFromObject(item, ids);
                                }
                            }
                        }
                    } else if (result instanceof Iterable) {
                        for (Object item : (Iterable<?>) result) {
                            extractCredentialIdFromObject(item, ids);
                        }
                    }
                } else if ("getBindings".equals(name)) {
                    Object result = m.invoke(action);
                    if (result instanceof Iterable) {
                        for (Object binding : (Iterable<?>) result) {
                            String id = invokeStringGetter(binding, "getCredentialsId");
                            if (id == null) id = invokeStringGetter(binding, "getCredentialId");
                            if (id != null && !id.isEmpty()) ids.add(id);
                        }
                    }
                }
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.log(Level.WARNING, "Error extracting credentials from action {0}: {1}",
                    new Object[]{action.getClass().getName(), e.getMessage()});
        }
    }

    /** Extract a credential ID from a single object (String, or object with getId()/getCredentialsId()). */
    private static void extractCredentialIdFromObject(Object item, Set<String> ids) {
        if (item instanceof String) {
            if (!((String) item).isEmpty()) ids.add((String) item);
        } else if (item != null) {
            String id = invokeStringGetter(item, "getId");
            if (id == null) id = invokeStringGetter(item, "getCredentialsId");
            if (id == null) id = invokeStringGetter(item, "getCredentialId");
            if (id != null && !id.isEmpty()) ids.add(id);
        }
    }

    private String[] parseCause(Cause cause) {
        String user = "SYSTEM";
        String type = "unknown";
        String desc = cause.getShortDescription();

        if (cause instanceof Cause.UserIdCause) {
            Cause.UserIdCause uc = (Cause.UserIdCause) cause;
            user = uc.getUserId() != null ? uc.getUserId() : "anonymous";
            type = "manual";
            desc = String.format("Manual trigger by %s", user);
        } else if (cause instanceof Cause.RemoteCause) {
            Cause.RemoteCause rc = (Cause.RemoteCause) cause;
            type = "remote-api";
            String addr = rc.getAddr();
            String note = rc.getNote();
            desc = String.format("Remote API trigger from %s%s", addr,
                    note != null ? " (note: " + note + ")" : "");
        } else if (cause instanceof Cause.UpstreamCause) {
            Cause.UpstreamCause uc = (Cause.UpstreamCause) cause;
            type = "upstream";
            desc = String.format("Upstream build %s #%d", uc.getUpstreamProject(), uc.getUpstreamBuild());
        } else {
            String className = cause.getClass().getSimpleName();
            if (className.contains("SCMTrigger")) type = "scm-polling";
            else if (className.contains("TimerTrigger")) type = "timer-cron";
            else if (className.contains("Replay")) type = "replay";
            else if (className.contains("Branch")) type = "branch-event";
            else type = className;
        }
        return new String[]{user, type, desc};
    }

    private String extractTriggerUser(Run<?, ?> run) {
        for (Cause cause : run.getCauses()) {
            if (cause instanceof Cause.UserIdCause) {
                String uid = ((Cause.UserIdCause) cause).getUserId();
                if (uid != null) return uid;
            }
        }
        return "SYSTEM";
    }

    private String extractTriggerType(Run<?, ?> run) {
        for (Cause cause : run.getCauses()) {
            return parseCause(cause)[1];
        }
        return "unknown";
    }

    private String extractParameters(Run<?, ?> run) {
        ParametersAction pa = run.getAction(ParametersAction.class);
        if (pa == null) return "";
        List<String> parts = new ArrayList<>();
        for (ParameterValue pv : pa.getParameters()) {
            String valStr = pv.isSensitive() ? "***" : String.valueOf(pv.getValue());
            parts.add(pv.getName() + "=" + valStr);
        }
        return String.join(", ", parts);
    }

    private static String currentUser() {
        // 0. Try extracting user from HTTP Basic Auth header (works even under ACL.SYSTEM impersonation)
        try {
            jakarta.servlet.http.HttpServletRequest req = RequestHolder.get();
            if (req != null) {
                String authHeader = req.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Basic ")) {
                    String decoded = new String(java.util.Base64.getDecoder().decode(authHeader.substring(6)), java.nio.charset.StandardCharsets.UTF_8);
                    String username = decoded.contains(":") ? decoded.substring(0, decoded.indexOf(':')) : decoded;
                    if (isRealUser(username)) return username;
                }
            }
        } catch (RuntimeException ignored) {}
        try {
            org.kohsuke.stapler.StaplerRequest2 staplerReq = org.kohsuke.stapler.Stapler.getCurrentRequest2();
            if (staplerReq != null) {
                String authHeader = staplerReq.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Basic ")) {
                    String decoded = new String(java.util.Base64.getDecoder().decode(authHeader.substring(6)), java.nio.charset.StandardCharsets.UTF_8);
                    String username = decoded.contains(":") ? decoded.substring(0, decoded.indexOf(':')) : decoded;
                    if (isRealUser(username)) return username;
                }
            }
        } catch (RuntimeException ignored) {}
        // 1. Try session-based Spring Security context
        try {
            jakarta.servlet.http.HttpServletRequest req = RequestHolder.get();
            if (req != null) {
                jakarta.servlet.http.HttpSession session = req.getSession(false);
                if (session != null) {
                    Object ctx = session.getAttribute("SPRING_SECURITY_CONTEXT");
                    if (ctx != null) {
                        java.lang.reflect.Method getAuth = ctx.getClass().getMethod("getAuthentication");
                        Object auth = getAuth.invoke(ctx);
                        if (auth != null) {
                            java.lang.reflect.Method getName = auth.getClass().getMethod("getName");
                            String name = (String) getName.invoke(auth);
                            if (isRealUser(name)) return name;
                        }
                    }
                }
                String remoteUser = req.getRemoteUser();
                if (isRealUser(remoteUser)) return remoteUser;
                java.security.Principal p = req.getUserPrincipal();
                if (p != null && isRealUser(p.getName())) return p.getName();
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
        // 2. Try Stapler request
        try {
            org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
            if (req != null) {
                String remoteUser = req.getRemoteUser();
                if (isRealUser(remoteUser)) return remoteUser;
                java.security.Principal p = req.getUserPrincipal();
                if (p != null && isRealUser(p.getName())) return p.getName();
            }
        } catch (RuntimeException ignored) {}
        // 3. Try Jenkins User.current()
        try {
            hudson.model.User u = hudson.model.User.current();
            if (u != null && isRealUser(u.getId())) return u.getId();
        } catch (RuntimeException ignored) {}
        // 4. Try Spring SecurityContext (thread-local)
        try {
            org.springframework.security.core.Authentication auth =
                    org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && isRealUser(auth.getName())) {
                return auth.getName();
            }
        } catch (RuntimeException ignored) {}
        return "SYSTEM";
    }

    private static boolean isRealUser(String name) {
        return name != null && !name.isEmpty()
                && !"SYSTEM".equalsIgnoreCase(name)
                && !"anonymous".equalsIgnoreCase(name)
                && !"anonymousUser".equals(name);
    }

    private static String formatDuration(long ms) {
        long sec = ms / 1000;
        if (sec < 60) return sec + "s";
        long min = sec / 60;
        sec %= 60;
        if (min < 60) return min + "m " + sec + "s";
        long hr = min / 60;
        min %= 60;
        return hr + "h " + min + "m " + sec + "s";
    }
}
