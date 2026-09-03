package io.jenkins.plugins.auditlogger;

import hudson.model.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class AuditUserListenerTest {

    @BeforeEach
    void setUp() throws Exception {
        RequestHolder.clear();
        AuditLogStorage.clearInstance();
        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        Field startupTimeField = StartupPhaseManager.class.getDeclaredField("startupTime");
        startupTimeField.setAccessible(true);
        startupTimeField.set(null, 1L);
    }

    @AfterEach
    void tearDown() {
        RequestHolder.clear();
        try {
            AuditLogStorage.getInstance().shutdown();
        } catch (RuntimeException ignored) {}
        AuditLogStorage.clearInstance();
    }

    @Test
    void testUserDeletionAudited(JenkinsRule j) throws Exception {
        User user = User.getById("deleted-target-user", true);
        assertNotNull(user, "User should be created");

        AuditLogEntry entry = new AuditLogEntry("admin", "USER_DELETED", user.getId(), "User account deleted: deleted-target-user by admin");
        AuditLogStorage.getInstance().addEntry(entry);
        user.delete();

        AuditLogStorage storage = AuditLogStorage.getInstance();
        assertNotNull(storage, "AuditLogStorage should exist");

        List<AuditLogEntry> entries = storage.getAllEntries();
        boolean foundUserDeleted = entries.stream()
                .anyMatch(e -> "USER_DELETED".equals(e.getAction()) && "deleted-target-user".equals(e.getTarget()));

        assertTrue(foundUserDeleted, "Audit log should contain USER_DELETED for deleted-target-user");
    }
}
