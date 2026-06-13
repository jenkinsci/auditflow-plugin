package io.jenkins.plugins.auditlogger;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Tests for AnomalyAlertValidator - comprehensive validation for anomaly alerts,
 * email addresses, and webhook URLs.
 */
public class AnomalyAlertValidatorTest {

    @Test
    void testValidAlertPassesValidation() {
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                "testuser",
                "Multiple failed login attempts detected",
                "CRITICAL",
                System.currentTimeMillis()
        );
        
        List<String> errors = AnomalyAlertValidator.validateAlert(alert);
        assertTrue(errors.isEmpty(), "Valid alert should have no errors");
    }

    @Test
    void testNullAlertFails() {
        List<String> errors = AnomalyAlertValidator.validateAlert(null);
        assertFalse(errors.isEmpty(), "Null alert should fail validation");
        assertTrue(errors.stream().anyMatch(e -> e.contains("null")), "Should report null alert");
    }

    @Test
    void testNullUserFails() {
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                null,
                "Details",
                "CRITICAL",
                System.currentTimeMillis()
        );
        
        List<String> errors = AnomalyAlertValidator.validateAlert(alert);
        assertFalse(errors.isEmpty(), "Null user should fail");
        assertTrue(errors.stream().anyMatch(e -> e.contains("user")), "Should report user error");
    }

    @Test
    void testEmptyUserFails() {
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                "   ",
                "Details",
                "CRITICAL",
                System.currentTimeMillis()
        );
        
        List<String> errors = AnomalyAlertValidator.validateAlert(alert);
        assertFalse(errors.isEmpty(), "Empty user should fail");
    }

    @Test
    void testInvalidSeverityFails() {
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                "user",
                "Details",
                "INVALID_SEVERITY",
                System.currentTimeMillis()
        );
        
        List<String> errors = AnomalyAlertValidator.validateAlert(alert);
        assertFalse(errors.isEmpty(), "Invalid severity should fail");
        assertTrue(errors.stream().anyMatch(e -> e.contains("severity")), "Should report severity error");
    }

    @Test
    void testValidSeveritiesPass() {
        String[] validSeverities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
        for (String severity : validSeverities) {
            AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                    AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                    "user",
                    "Details",
                    severity,
                    System.currentTimeMillis()
            );
            
            List<String> errors = AnomalyAlertValidator.validateAlert(alert);
            assertTrue(errors.isEmpty(), "Severity '" + severity + "' should be valid");
        }
    }

    @Test
    void testFutureTimestampFails() {
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                "user",
                "Details",
                "CRITICAL",
                System.currentTimeMillis() + 10_000  // 10 seconds in future
        );
        
        List<String> errors = AnomalyAlertValidator.validateAlert(alert);
        assertFalse(errors.isEmpty(), "Future timestamp should fail");
        assertTrue(errors.stream().anyMatch(e -> e.contains("future")), "Should report future timestamp");
    }

    @Test
    void testZeroTimestampFails() {
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                "user",
                "Details",
                "CRITICAL",
                0
        );
        
        List<String> errors = AnomalyAlertValidator.validateAlert(alert);
        assertFalse(errors.isEmpty(), "Zero timestamp should fail");
    }

    // Email validation tests

    @Test
    void testValidEmailPassesValidation() {
        List<String> errors = AnomalyAlertValidator.validateEmailAddresses("test@example.com");
        List<String> critical = AnomalyAlertValidator.getCriticalErrors(errors);
        assertTrue(critical.isEmpty(), "Valid email should pass");
    }

    @Test
    void testMultipleValidEmailsPass() {
        List<String> errors = AnomalyAlertValidator.validateEmailAddresses(
                "test1@example.com, test2@example.com, test3@example.org"
        );
        List<String> critical = AnomalyAlertValidator.getCriticalErrors(errors);
        assertTrue(critical.isEmpty(), "Multiple valid emails should pass");
    }

    @Test
    void testInvalidEmailFails() {
        List<String> errors = AnomalyAlertValidator.validateEmailAddresses("invalid-email");
        assertFalse(errors.isEmpty(), "Invalid email should fail");
    }

    @Test
    void testNullEmailAddressesFails() {
        List<String> errors = AnomalyAlertValidator.validateEmailAddresses(null);
        assertFalse(errors.isEmpty(), "Null email addresses should fail");
    }

    @Test
    void testEmptyEmailAddressesFails() {
        List<String> errors = AnomalyAlertValidator.validateEmailAddresses("   ");
        assertFalse(errors.isEmpty(), "Empty email addresses should fail");
    }

    @Test
    void testMixedValidInvalidEmailsFails() {
        List<String> errors = AnomalyAlertValidator.validateEmailAddresses(
                "valid@example.com, invalid-email, another@valid.org"
        );
        assertFalse(errors.isEmpty(), "Mix of valid and invalid should fail");
    }

    // Webhook URL validation tests

    @Test
    void testValidHttpsWebhookUrlPasses() {
        List<String> errors = AnomalyAlertValidator.validateWebhookUrl(
                "https://hooks.example.com/webhook"
        );
        List<String> critical = AnomalyAlertValidator.getCriticalErrors(errors);
        assertTrue(critical.isEmpty(), "Valid HTTPS webhook URL should pass");
    }

    @Test
    void testHttpWebhookUrlPassesWithWarning() {
        List<String> errors = AnomalyAlertValidator.validateWebhookUrl(
                "http://hooks.example.com/webhook"
        );
        List<String> critical = AnomalyAlertValidator.getCriticalErrors(errors);
        assertTrue(critical.isEmpty(), "HTTP webhook URL should pass (with warning)");
        assertTrue(errors.stream().anyMatch(e -> e.startsWith("Warning:")), 
                "Should have HTTPS warning");
    }

    @Test
    void testInvalidProtocolFails() {
        List<String> errors = AnomalyAlertValidator.validateWebhookUrl(
                "ftp://hooks.example.com/webhook"
        );
        assertFalse(errors.isEmpty(), "FTP protocol should fail");
    }

    @Test
    void testNullWebhookUrlFails() {
        List<String> errors = AnomalyAlertValidator.validateWebhookUrl(null);
        assertFalse(errors.isEmpty(), "Null webhook URL should fail");
    }

    @Test
    void testEmptyWebhookUrlFails() {
        List<String> errors = AnomalyAlertValidator.validateWebhookUrl("   ");
        assertFalse(errors.isEmpty(), "Empty webhook URL should fail");
    }

    @Test
    void testLocalhostWebhookUrlWarning() {
        List<String> errors = AnomalyAlertValidator.validateWebhookUrl(
                "http://localhost:8080/webhook"
        );
        assertTrue(errors.stream().anyMatch(e -> e.contains("localhost")), 
                "Should warn about localhost");
    }

    @Test
    void testMalformedUrlFails() {
        List<String> errors = AnomalyAlertValidator.validateWebhookUrl(
                "http://invalid url with spaces"
        );
        assertFalse(errors.isEmpty(), "Malformed URL should fail");
    }

    // Webhook payload validation tests

    @Test
    void testValidJsonPayloadPasses() {
        String payload = "{\"type\":\"BRUTE_FORCE_LOGIN\",\"severity\":\"CRITICAL\"}";
        List<String> errors = AnomalyAlertValidator.validateWebhookPayload(payload);
        List<String> critical = AnomalyAlertValidator.getCriticalErrors(errors);
        assertTrue(critical.isEmpty(), "Valid JSON payload should pass");
    }

    @Test
    void testNullPayloadFails() {
        List<String> errors = AnomalyAlertValidator.validateWebhookPayload(null);
        assertFalse(errors.isEmpty(), "Null payload should fail");
    }

    @Test
    void testEmptyPayloadFails() {
        List<String> errors = AnomalyAlertValidator.validateWebhookPayload("   ");
        assertFalse(errors.isEmpty(), "Empty payload should fail");
    }

    @Test
    void testMissingOpenBraceFails() {
        List<String> errors = AnomalyAlertValidator.validateWebhookPayload(
                "\"type\":\"test\"}"
        );
        assertFalse(errors.isEmpty(), "Missing opening brace should fail");
    }

    @Test
    void testMissingCloseBraceFails() {
        List<String> errors = AnomalyAlertValidator.validateWebhookPayload(
                "{\"type\":\"test\""
        );
        assertFalse(errors.isEmpty(), "Missing closing brace should fail");
    }

    @Test
    void testUnclosedStringFails() {
        List<String> errors = AnomalyAlertValidator.validateWebhookPayload(
                "{\"type\":\"unclosed"
        );
        assertFalse(errors.isEmpty(), "Unclosed string should fail");
    }

    // Sanitization tests

    @Test
    void testSanitizeInputRemovesNewlines() {
        String input = "test\nwith\nnewlines";
        String sanitized = AnomalyAlertValidator.sanitizeInput(input);
        assertFalse(sanitized.contains("\n"), "Newlines should be removed");
    }

    @Test
    void testSanitizeInputEscapesQuotes() {
        String input = "test\"with\"quotes";
        String sanitized = AnomalyAlertValidator.sanitizeInput(input);
        assertTrue(sanitized.contains("\\\""), "Quotes should be escaped");
    }

    @Test
    void testSanitizeInputEscapesBackslashes() {
        String input = "test\\with\\backslashes";
        String sanitized = AnomalyAlertValidator.sanitizeInput(input);
        assertTrue(sanitized.contains("\\\\"), "Backslashes should be escaped");
    }

    @Test
    void testSanitizeNullInputReturnsEmpty() {
        String sanitized = AnomalyAlertValidator.sanitizeInput(null);
        assertEquals("", sanitized, "Null input should return empty string");
    }

    // Utility tests

    @Test
    void testIsValidWithEmptyErrorsList() {
        assertTrue(AnomalyAlertValidator.isValid(new java.util.ArrayList<>()), 
                "Empty error list means valid");
    }

    @Test
    void testIsValidWithErrors() {
        java.util.List<String> errors = new java.util.ArrayList<>();
        errors.add("Error 1");
        assertFalse(AnomalyAlertValidator.isValid(errors), 
                "Non-empty error list means invalid");
    }

    @Test
    void testGetCriticalErrorsFiltersWarnings() {
        java.util.List<String> errors = new java.util.ArrayList<>();
        errors.add("Warning: This is a warning");
        errors.add("This is a critical error");
        
        List<String> critical = AnomalyAlertValidator.getCriticalErrors(errors);
        assertEquals(1, critical.size(), "Should have one critical error");
        assertEquals("This is a critical error", critical.get(0), "Should extract critical error");
    }
}
