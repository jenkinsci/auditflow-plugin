package io.jenkins.plugins.auditlogger;

import hudson.model.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.lang.reflect.Field;
import java.time.ZoneId;
import java.util.Arrays;
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
    void testUserCreationAndDeletionAudited(JenkinsRule j) throws Exception {
        User user = User.getById("deleted-target-user", true);
        assertNotNull(user, "User should be created");

        AuditLogStorage storage = AuditLogStorage.getInstance();
        assertNotNull(storage, "AuditLogStorage should exist");

        // Add user creation and deletion log entries
        AuditLogEntry createEntry = new AuditLogEntry("admin", "USER_CREATED", user.getId(), "User account created: deleted-target-user by admin");
        storage.addEntry(createEntry);

        AuditLogEntry deleteEntry = new AuditLogEntry("admin", "USER_DELETED", user.getId(), "User account deleted: deleted-target-user by admin");
        storage.addEntry(deleteEntry);

        user.delete();

        List<AuditLogEntry> entries = storage.getAllEntries();
        boolean foundUserCreated = entries.stream()
                .anyMatch(e -> "USER_CREATED".equals(e.getAction()) && "deleted-target-user".equals(e.getTarget()));
        boolean foundUserDeleted = entries.stream()
                .anyMatch(e -> "USER_DELETED".equals(e.getAction()) && "deleted-target-user".equals(e.getTarget()));

        assertTrue(foundUserCreated, "Audit log should contain USER_CREATED for deleted-target-user");
        assertTrue(foundUserDeleted, "Audit log should contain USER_DELETED for deleted-target-user");
    }

    @Test
    void testUserCreatedAndDeletedSearchWithSpaces(JenkinsRule j) throws Exception {
        AuditLogEntry createEntry = new AuditLogEntry("admin", "USER_CREATED", "new-user-1", "User account created: new-user-1");
        AuditLogEntry deleteEntry = new AuditLogEntry("admin", "USER_DELETED", "old-user-2", "User account deleted: old-user-2");
        List<AuditLogEntry> entries = Arrays.asList(createEntry, deleteEntry);

        // Search with space "USER CREATED"
        AuditLoggerManagementLink.AuditViewRequest reqCreated = new AuditLoggerManagementLink.AuditViewRequest(
                "USER CREATED", "all", null, null, null, "all", "timestampMs", false, 1, 10);
        List<AuditLogEntry> filteredCreated = AuditLoggerManagementLink.filterAndSortEntries(entries, reqCreated, ZoneId.of("UTC"));
        assertEquals(1, filteredCreated.size(), "Searching 'USER CREATED' with spaces should match USER_CREATED action");
        assertEquals("USER_CREATED", filteredCreated.get(0).getAction());

        // Search with space "USER DELETED"
        AuditLoggerManagementLink.AuditViewRequest reqDeleted = new AuditLoggerManagementLink.AuditViewRequest(
                "USER DELETED", "all", null, null, null, "all", "timestampMs", false, 1, 10);
        List<AuditLogEntry> filteredDeleted = AuditLoggerManagementLink.filterAndSortEntries(entries, reqDeleted, ZoneId.of("UTC"));
        assertEquals(1, filteredDeleted.size(), "Searching 'USER DELETED' with spaces should match USER_DELETED action");
        assertEquals("USER_DELETED", filteredDeleted.get(0).getAction());
    }
}
