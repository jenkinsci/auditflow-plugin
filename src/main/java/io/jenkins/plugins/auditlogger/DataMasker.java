package io.jenkins.plugins.auditlogger;

import java.util.regex.Pattern;

/**
 * Data privacy masking layer. Masks sensitive information before log persistence.
 * Patterns: passwords, API tokens, SSH keys, emails, credit card numbers.
 */
public class DataMasker {

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "([Pp]assword|[Pp]wd|[Pp]ass|secret|token|api[_-]?key)\\s*[=:]\\s*[\"']?([^\"'\\s,}]+)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SSH_KEY_PATTERN = Pattern.compile(
            "(-----BEGIN[\\s\\w]+-----)[\\s\\S]+(-----END[\\s\\w]+-----)",
            Pattern.MULTILINE);

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");

    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile(
            "\\b(?:\\d{4}[ -]?){3}\\d{4}\\b");

    private static final Pattern TOKEN_VALUE_PATTERN = Pattern.compile(
            "(?i)(token|api_key|apikey|bearer|authorization)\\s*[:=]\\s*[\"']?([A-Za-z0-9._-]+)[\"']?");

    public static void maskEntry(AuditLogEntry entry) {
        if (entry == null) return;
        String details = entry.getDetails();
        if (details != null && !details.isEmpty()) {
            entry.setDetails(maskString(details));
        }
    }

    public static String maskString(String text) {
        if (text == null || text.isEmpty()) return text;

        text = PASSWORD_PATTERN.matcher(text).replaceAll("$1=[MASKED]");
        text = SSH_KEY_PATTERN.matcher(text).replaceAll("$1[...MASKED SSH KEY...]$2");

        AuditLoggerConfiguration config = AuditLoggerConfiguration.get();
        if (config != null && config.isMaskEmailAddresses()) {
            text = maskEmails(text);
        }
        if (config == null || config.isMaskCreditCards()) {
            text = CREDIT_CARD_PATTERN.matcher(text).replaceAll("[MASKED CARD]");
        }

        text = TOKEN_VALUE_PATTERN.matcher(text).replaceAll("$1=[MASKED]");
        return text;
    }

    static String maskEmails(String text) {
        return EMAIL_PATTERN.matcher(text).replaceAll(match -> {
            String email = match.group();
            int atIndex = email.indexOf('@');
            if (atIndex >= 1) {
                return email.charAt(0) + "****" + email.substring(atIndex);
            }
            return email;
        });
    }

    public static boolean containsSensitiveData(String text) {
        if (text == null || text.isEmpty()) return false;
        return PASSWORD_PATTERN.matcher(text).find()
                || SSH_KEY_PATTERN.matcher(text).find()
                || CREDIT_CARD_PATTERN.matcher(text).find();
    }
}
