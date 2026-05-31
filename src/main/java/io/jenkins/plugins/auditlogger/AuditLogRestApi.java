package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import hudson.model.RootAction;
import jakarta.servlet.ServletException;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.kohsuke.stapler.verb.GET;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * REST API endpoint for audit logs at /auditflow/api.
 *
 * SECURITY FIX: Uses RootAction (requires authentication) instead of UnprotectedRootAction.
 * Additional admin check enforces Jenkins.ADMINISTER permission.
 */
@Extension
public class AuditLogRestApi implements RootAction {
    private static final Logger LOGGER = Logger.getLogger(AuditLogRestApi.class.getName());

    @Override
    public String getUrlName() {
        return "auditflow";
    }

    @Override
    public String getDisplayName() {
        return null; // hide from sidebar
    }

    @Override
    public String getIconFileName() {
        return null; // hide from sidebar
    }

    @GET
    public void doApi(StaplerRequest2 req, StaplerResponse2 resp) throws IOException, ServletException {
        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        if (config == null || !config.isEnableAuditApi()) {
            resp.setStatus(403);
            resp.setContentType("application/json; charset=UTF-8");
            resp.getWriter().write("{\"error\": \"Audit API is disabled\"}");
            return;
        }

        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null || !jenkins.hasPermission(Jenkins.ADMINISTER)) {
            resp.setStatus(403);
            resp.setContentType("application/json; charset=UTF-8");
            resp.getWriter().write("{\"error\": \"Admin permission required\"}");
            return;
        }

        try {
            String user = req.getParameter("user");
            String action = req.getParameter("action");
            Long startTime = parseLong(req.getParameter("startTime"));
            Long endTime = parseLong(req.getParameter("endTime"));
            int limit = parseInt(req.getParameter("limit"), 10000);
            if (limit < 1) limit = 1;
            if (limit > 50000) limit = 50000;

            // Validate time range
            if (startTime != null && endTime != null && startTime > endTime) {
                resp.setStatus(400);
                resp.setContentType("application/json; charset=UTF-8");
                resp.getWriter().write("{\"error\": \"startTime must be <= endTime\"}");
                return;
            }

            List<AuditLogEntry> entries = AuditLogStorage.getInstance()
                    .filterEntries(user, action, startTime, endTime);

            // Cap results
            if (entries.size() > limit) {
                entries = entries.subList(entries.size() - limit, entries.size());
            }

            JSONArray jsonArray = new JSONArray();
            for (AuditLogEntry entry : entries) {
                JSONObject json = new JSONObject();
                json.put("timestamp", entry.getTimestamp());
                json.put("username", entry.getUsername());
                json.put("action", entry.getAction());
                json.put("target", entry.getTarget());
                json.put("details", entry.getDetails());
                json.put("severity", entry.getSeverity());
                json.put("sourceIp", entry.getSourceIp());
                json.put("userAgent", entry.getUserAgent());
                if (entry.getSessionId() != null) {
                    json.put("sessionId", entry.getSessionId());
                }
                jsonArray.add(json);
            }

            // hey, grabbing our new anomalies from the detector!
            AnomalyDetector detector = AuditLogStorage.getInstance().getAnomalyDetector();
            List<AnomalyDetector.AnomalyAlert> alerts = detector.getAlerts(10);
            JSONArray anomalyArray = new JSONArray();
            for (AnomalyDetector.AnomalyAlert alert : alerts) {
                JSONObject json = new JSONObject();
                json.put("type", alert.type.name());
                json.put("user", alert.user);
                json.put("details", alert.details);
                json.put("timestamp", alert.timestamp);
                json.put("severity", alert.severity);
                anomalyArray.add(json);
            }

            resp.setContentType("application/json; charset=UTF-8");
            resp.getWriter().write("{\"status\": \"success\", \"count\": " + jsonArray.size()
                    + ", \"logs\": " + jsonArray.toString() 
                    + ", \"anomalies\": " + anomalyArray.toString() + "}");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error in audit API", e);
            resp.setStatus(500);
            resp.setContentType("application/json; charset=UTF-8");
            resp.getWriter().write("{\"error\": \"Internal server error\"}");
        }
    }

    private static Long parseLong(String s) {
        if (s == null || s.isEmpty()) return null;
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static int parseInt(String s, int defaultValue) {
        if (s == null || s.isEmpty()) return defaultValue;
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
