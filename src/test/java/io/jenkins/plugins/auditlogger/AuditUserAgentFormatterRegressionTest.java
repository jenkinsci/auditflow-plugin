package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditUserAgentFormatterRegressionTest {

    @Test
    void authenticationDetailsKeepFullUserAgentWhileStrippingControlCharacters() {
        String userAgent = "Mozilla/5.0 " + "x".repeat(120) + "\r\nTabbed\tSuffix";

        String details = AuditSecurityListener.buildAuthenticationDetail("session", userAgent, false, false);

        assertTrue(details.contains(AuditUserAgentFormatter.normalizeForDetails(userAgent)));
        assertTrue(details.length() > 80);
        assertFalse(details.contains("\r"));
        assertFalse(details.contains("\n"));
        assertFalse(details.contains("\t"));
        assertFalse(details.contains("..."));
    }

    @Test
    void deferredAuthEnrichmentUsesFullSanitizedUserAgent() {
        String details = "Authenticated (method: session, UA: N/A)";
        String userAgent = "Agent\r\nTabbed\tSuffix";

        assertEquals(
                "Authenticated (method: session, UA: Agent  Tabbed Suffix)",
                AuditUserAgentFormatter.replaceMissingInDetails(details, userAgent));
    }
}