package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StartupPhaseManagerTest {

    @Test
    void recentTargetEntriesExpireAfterDuplicateWindow() {
        StartupPhaseManager.resetRecentLogsForTests();

        StartupPhaseManager.markAsLogged("ThemeManagerPageDecorator", 1_000L);

        assertTrue(StartupPhaseManager.wasRecentlyLogged("ThemeManagerPageDecorator", 2_500L));
        assertFalse(StartupPhaseManager.wasRecentlyLogged("ThemeManagerPageDecorator", 4_100L));
        assertFalse(StartupPhaseManager.wasRecentlyLogged("ThemeManagerPageDecorator", 4_100L));
    }
}