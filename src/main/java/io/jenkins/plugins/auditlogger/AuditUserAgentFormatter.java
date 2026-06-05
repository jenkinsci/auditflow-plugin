package io.jenkins.plugins.auditlogger;

final class AuditUserAgentFormatter {
    private AuditUserAgentFormatter() {
    }

    static String normalizeForDetails(String userAgent) {
        if (userAgent == null) {
            return "N/A";
        }
        return userAgent.replaceAll("[\\r\\n\\t]", " ");
    }

    static String replaceMissingInDetails(String details, String userAgent) {
        if (details == null || !details.contains("UA: N/A")) {
            return details;
        }
        return details.replace("UA: N/A", "UA: " + normalizeForDetails(userAgent));
    }
}