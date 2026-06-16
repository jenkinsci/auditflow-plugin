package io.jenkins.plugins.auditlogger;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Comprehensive validator for anomaly alerts, email addresses, and webhook URLs.
 * Ensures data integrity and security before sending notifications.
 */
public class AnomalyAlertValidator {
    private static final int MAX_EMAIL_LENGTH = 254;
    private static final int MAX_URL_LENGTH = 2048;
    private static final int MAX_USER_LENGTH = 256;
    private static final int MAX_DETAILS_LENGTH = 2048;
    private static final int MAX_SEVERITY_LENGTH = 32;
    
    // Email regex: Simple validation (RFC 5322 simplified)
    private static final Pattern EMAIL_PATTERN = 
        Pattern.compile("^[A-Za-z0-9+._%-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    
    // URL validation: Basic HTTPS/HTTP check
    private static final Pattern URL_PATTERN = 
        Pattern.compile("^https?://[A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+$");
    
    // Severity levels enum
    public enum SeverityLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    /**
     * Validates an anomaly alert for completeness and data integrity.
     * @param alert the anomaly alert to validate
     * @return list of validation errors (empty if valid)
     */
    public static List<String> validateAlert(AnomalyDetector.AnomalyAlert alert) {
        List<String> errors = new ArrayList<>();
        
        if (alert == null) {
            errors.add("Alert cannot be null");
            return errors;
        }
        
        // Validate type
        if (alert.type == null) {
            errors.add("Alert type cannot be null");
        }
        
        // Validate user
        if (alert.user == null || alert.user.trim().isEmpty()) {
            errors.add("Alert user cannot be null or empty");
        } else if (alert.user.length() > MAX_USER_LENGTH) {
            errors.add("Alert user exceeds maximum length of " + MAX_USER_LENGTH);
        }
        
        // Validate details
        if (alert.details == null || alert.details.trim().isEmpty()) {
            errors.add("Alert details cannot be null or empty");
        } else if (alert.details.length() > MAX_DETAILS_LENGTH) {
            errors.add("Alert details exceeds maximum length of " + MAX_DETAILS_LENGTH);
        }
        
        // Validate severity
        if (alert.severity == null || alert.severity.trim().isEmpty()) {
            errors.add("Alert severity cannot be null or empty");
        } else if (!isValidSeverity(alert.severity)) {
            errors.add("Alert severity must be one of: LOW, MEDIUM, HIGH, CRITICAL. Got: " + alert.severity);
        } else if (alert.severity.length() > MAX_SEVERITY_LENGTH) {
            errors.add("Alert severity exceeds maximum length of " + MAX_SEVERITY_LENGTH);
        }
        
        // Validate timestamp
        if (alert.timestamp <= 0) {
            errors.add("Alert timestamp must be positive (milliseconds since epoch)");
        }
        if (alert.timestamp > System.currentTimeMillis() + 5_000) {
            errors.add("Alert timestamp cannot be in the future (5-second tolerance)");
        }
        
        return errors;
    }
    
    /**
     * Validates a list of email addresses.
     * @param emailAddresses comma-separated email addresses
     * @return list of validation errors (empty if valid)
     */
    public static List<String> validateEmailAddresses(String emailAddresses) {
        List<String> errors = new ArrayList<>();
        
        if (emailAddresses == null || emailAddresses.trim().isEmpty()) {
            errors.add("Email addresses cannot be null or empty");
            return errors;
        }
        
        if (emailAddresses.length() > MAX_EMAIL_LENGTH * 10) {
            errors.add("Email address list exceeds maximum total length");
        }
        
        String[] addresses = emailAddresses.split(",");
        int count = 0;
        for (String address : addresses) {
            String trimmed = address.trim();
            if (!trimmed.isEmpty()) {
                count++;
                if (!validateSingleEmail(trimmed)) {
                    errors.add("Invalid email format: " + trimmed);
                }
                if (trimmed.length() > MAX_EMAIL_LENGTH) {
                    errors.add("Email address exceeds maximum length of " + MAX_EMAIL_LENGTH + ": " + trimmed);
                }
            }
        }
        
        if (count == 0) {
            errors.add("At least one valid email address is required");
        }
        
        return errors;
    }
    
    /**
     * Validates a single email address.
     * @param email the email address to validate
     * @return true if valid, false otherwise
     */
    public static boolean validateSingleEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email).matches();
    }
    
    /**
     * Validates a webhook URL.
     * @param webhookUrl the webhook URL to validate
     * @return list of validation errors (empty if valid)
     */
    public static List<String> validateWebhookUrl(String webhookUrl) {
        List<String> errors = new ArrayList<>();
        
        if (webhookUrl == null || webhookUrl.trim().isEmpty()) {
            errors.add("Webhook URL cannot be null or empty");
            return errors;
        }
        
        webhookUrl = webhookUrl.trim();
        
        // Check length
        if (webhookUrl.length() > MAX_URL_LENGTH) {
            errors.add("Webhook URL exceeds maximum length of " + MAX_URL_LENGTH);
            return errors;
        }
        
        // Check protocol
        if (!webhookUrl.startsWith("http://") && !webhookUrl.startsWith("https://")) {
            errors.add("Webhook URL must use HTTP or HTTPS protocol");
            return errors;
        }
        
        // Prefer HTTPS for security
        if (!webhookUrl.startsWith("https://")) {
            errors.add("Warning: Webhook URL should use HTTPS for security (currently using HTTP)");
        }
        
        // Check URL format with basic regex
        if (!URL_PATTERN.matcher(webhookUrl).matches()) {
            errors.add("Webhook URL has invalid format");
            return errors;
        }
        
        // Try to parse as URL
        try {
            URL url = new URL(webhookUrl);
            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                errors.add("Webhook URL must have a valid host");
            }
            // Check for localhost/127.0.0.1 (usually not intended for production)
            if ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)) {
                errors.add("Warning: Webhook URL points to localhost (not suitable for production)");
            }
        } catch (MalformedURLException e) {
            errors.add("Webhook URL is malformed: " + e.getMessage());
        }
        
        return errors;
    }
    
    /**
     * Validates webhook JSON payload for structure and size.
     * @param jsonPayload the JSON payload to validate
     * @return list of validation errors (empty if valid)
     */
    public static List<String> validateWebhookPayload(String jsonPayload) {
        List<String> errors = new ArrayList<>();
        
        if (jsonPayload == null || jsonPayload.trim().isEmpty()) {
            errors.add("Webhook payload cannot be null or empty");
            return errors;
        }
        
        // Check payload size (reasonable limit for webhook)
        if (jsonPayload.length() > 65_536) { // 64KB limit
            errors.add("Webhook payload exceeds maximum size of 64KB");
        }
        
        // Basic JSON validation (not using external libraries)
        String trimmed = jsonPayload.trim();
        if (!trimmed.startsWith("{")) {
            errors.add("Webhook payload must be a JSON object (must start with '{')");
        }
        if (!trimmed.endsWith("}")) {
            errors.add("Webhook payload must be a JSON object (must end with '}')");
        }
        
        // Check for unescaped quotes (basic validation)
        int bracketCount = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
            } else if (!inString) {
                if (c == '{') bracketCount++;
                else if (c == '}') bracketCount--;
            }
        }
        
        if (bracketCount != 0) {
            errors.add("Webhook payload has unmatched braces");
        }
        if (inString) {
            errors.add("Webhook payload has unclosed string");
        }
        
        return errors;
    }
    
    /**
     * Validates alert type.
     * @param type the anomaly type
     * @return true if valid, false otherwise
     */
    public static boolean isValidAlertType(String type) {
        if (type == null || type.isEmpty()) {
            return false;
        }
        try {
            AnomalyDetector.AnomalyType.valueOf(type);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
    
    /**
     * Validates severity level.
     * @param severity the severity level string
     * @return true if valid, false otherwise
     */
    public static boolean isValidSeverity(String severity) {
        if (severity == null || severity.isEmpty()) {
            return false;
        }
        try {
            SeverityLevel.valueOf(severity);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
    
    /**
     * Sanitizes user input to prevent injection attacks.
     * @param input the user input
     * @return sanitized input
     */
    public static String sanitizeInput(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "")
                .replace("\t", " ");
    }
    
    /**
     * Checks if all validations pass.
     * @param errors list of validation errors
     * @return true if no errors, false otherwise
     */
    public static boolean isValid(List<String> errors) {
        return errors.isEmpty();
    }
    
    /**
     * Returns critical errors only (excluding warnings).
     * @param errors list of all validation errors
     * @return list of critical errors only
     */
    public static List<String> getCriticalErrors(List<String> errors) {
        List<String> critical = new ArrayList<>();
        for (String error : errors) {
            if (!error.startsWith("Warning:")) {
                critical.add(error);
            }
        }
        return critical;
    }
}
