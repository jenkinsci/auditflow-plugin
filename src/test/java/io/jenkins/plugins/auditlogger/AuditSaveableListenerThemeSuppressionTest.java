package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditSaveableListenerThemeSuppressionTest {

    @Test
    void suppressesExplicitThemeUserPropertySaves() {
        assertTrue(AuditSaveableListener.shouldSuppressThemeUserPreferenceLog(
                "io.jenkins.plugins.thememanager.ThemeUserProperty",
                false,
                "",
                Set.of()));
    }

    @Test
    void suppressesUserThemeSwitchRequests() {
        assertTrue(AuditSaveableListener.shouldSuppressThemeUserPreferenceLog(
                "hudson.model.User",
                true,
                "/theme/set",
                Set.of("value")));
    }

    @Test
    void keepsGlobalThemeDecoratorSavesAuditable() {
        assertFalse(AuditSaveableListener.shouldSuppressThemeUserPreferenceLog(
                "io.jenkins.plugins.thememanager.ThemeManagerPageDecorator",
                false,
                "/manage/configure",
                Set.of("theme")));
    }

    @Test
    void suppressesSystemSaveablesDuringConfigurationSubmitRequests() {
        assertTrue(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(true, "/configure"));
        assertTrue(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(true, "/manage/configure"));
    }

    @Test
    void keepsNonConfigurationSystemSavesAuditable() {
        assertFalse(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(true, "/job/example/config.xml"));
        assertFalse(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(false, "/configure"));
    }

    @Test
    void detailedConfigChangeSummaryUsesReadableDiffs() {
        LinkedHashMap<String, String> previous = new LinkedHashMap<>();
        previous.put("Email alerts", "disabled");
        previous.put("Alert recipient count", "1");

        LinkedHashMap<String, String> current = new LinkedHashMap<>();
        current.put("Email alerts", "enabled");
        current.put("Alert recipient count", "2");

        List<String> changes = AuditSaveableListener.describeConfigurationChanges(previous, current);
        assertEquals(List.of(
                "Email alerts: disabled -> enabled",
                "Alert recipient count: 1 -> 2"), changes);
    }
}
