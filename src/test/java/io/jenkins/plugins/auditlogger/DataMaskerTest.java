package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class DataMaskerTest {

    @Test
    public void testMaskPasswordsAndTokens() {
        String input = "User updated config with password=SuperSecret123 and token: 'my-api-token-999'";
        String masked = DataMasker.maskString(input);
        assertFalse(masked.contains("SuperSecret123"));
        assertFalse(masked.contains("my-api-token-999"));
        assertTrue(masked.contains("[MASKED]"));
    }

    @Test
    public void testMaskSshKey() {
        String sshKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAz5...\n-----END RSA PRIVATE KEY-----";
        String masked = DataMasker.maskString(sshKey);
        assertFalse(masked.contains("MIIEowIBAAKCAQEAz5"));
        assertTrue(masked.contains("[...MASKED SSH KEY...]"));
    }

    @Test
    public void testMaskCreditCard() {
        String input = "Payment details with card 4111-2222-3333-4444 submitted";
        String masked = DataMasker.maskString(input);
        assertFalse(masked.contains("4111-2222-3333-4444"));
        assertTrue(masked.contains("[MASKED CARD]"));
    }

    @Test
    public void testMaskEntry() {
        AuditLogEntry entry = new AuditLogEntry("admin", "CONFIG_UPDATED", "system", "apiKey=secretKey98765");
        DataMasker.maskEntry(entry);
        assertFalse(entry.getDetails().contains("secretKey98765"));
        assertTrue(entry.getDetails().contains("[MASKED]"));
    }

    @Test
    public void testContainsSensitiveData() {
        assertTrue(DataMasker.containsSensitiveData("password=12345"));
        assertTrue(DataMasker.containsSensitiveData("card: 1111-2222-3333-4444"));
        assertTrue(DataMasker.containsSensitiveData("-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----"));
        assertFalse(DataMasker.containsSensitiveData("normal harmless build log output"));
        assertFalse(DataMasker.containsSensitiveData(null));
        assertFalse(DataMasker.containsSensitiveData(""));
    }

    @Test
    public void testNullAndEmptyHandling() {
        assertNull(DataMasker.maskString(null));
        assertEquals("", DataMasker.maskString(""));
        DataMasker.maskEntry(null); // Should not throw
    }
}
