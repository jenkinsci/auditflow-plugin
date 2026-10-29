package io.jenkins.plugins.auditlogger;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import java.lang.reflect.Type;

/**
 * Gson serializer for AuditLogEntry — includes all audit-compliance fields.
 */
public class AuditLogEntrySerializer implements JsonSerializer<AuditLogEntry> {

    @Override
    public JsonElement serialize(AuditLogEntry src, Type typeOfSrc, JsonSerializationContext context) {
        if (src == null) {
            return com.google.gson.JsonNull.INSTANCE;
        }
        JsonObject obj = new JsonObject();
        obj.addProperty("timestamp", src.getFormattedTimestamp());
        obj.addProperty("timestampMs", src.getTimestamp());
        obj.addProperty("user", src.getUsername());
        obj.addProperty("action", src.getAction());
        obj.addProperty("target", src.getTarget());
        obj.addProperty("details", src.getDetails() != null ? src.getDetails() : "");
        obj.addProperty("readable", src.getReadableTimestamp());
        obj.addProperty("sourceIp", src.getSourceIp() != null ? src.getSourceIp() : "");
        obj.addProperty("authMethod", src.getAuthMethod() != null ? src.getAuthMethod() : "");
        obj.addProperty("triggerType", src.getTriggerType() != null ? src.getTriggerType() : "");
        obj.addProperty("sessionId", src.getSessionId() != null ? src.getSessionId() : "");
        obj.addProperty("userAgent", src.getUserAgent() != null ? src.getUserAgent() : "");
        obj.addProperty("severity", src.getSeverity() != null ? src.getSeverity() : "INFO");
        return obj;
    }
}
