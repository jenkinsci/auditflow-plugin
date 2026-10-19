package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;

import java.util.Set;

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
    void suppressesSystemSaveablesDuringConfigSubmitRequests() {
        assertTrue(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(true, "/configSubmit"));
        assertTrue(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(true, "/manage/configSubmit"));
    }

    @Test
    void keepsNonConfigurationSystemSavesAuditable() {
        assertFalse(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(true, "/job/example/config.xml"));
        assertFalse(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(false, "/configure"));
        assertFalse(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(true, null));
        assertFalse(AuditSaveableListener.shouldSuppressRequestScopedSystemConfigSave(true, ""));
    }

    public static class ResourceDomainConfiguration implements hudson.model.Saveable {
        @Override public void save() {}
    }

    public static class GlobalMatrixAuthorizationStrategy implements hudson.model.Saveable {
        @Override public void save() {}
    }

    public static class HudsonPrivateSecurityRealm implements hudson.model.Saveable {
        @Override public void save() {}
    }

    public static class RoleBasedAuthorizationStrategy implements hudson.model.Saveable {
        @Override public void save() {}
    }

    public static class StandardGlobalConfig implements hudson.model.Saveable {
        @Override public void save() {}
    }

    @Test
    void resourceDomainConfigIsNotTreatedAsSecurityConfig() {
        assertFalse(AuditSaveableListener.isSecurityConfiguration(new ResourceDomainConfiguration()),
                "ResourceDomainConfiguration must not be classified as a security config change");
    }

    @Test
    void authenticatorsAndAuthorizationStrategiesAreTreatedAsSecurityConfig() {
        assertTrue(AuditSaveableListener.isSecurityConfiguration(new GlobalMatrixAuthorizationStrategy()),
                "GlobalMatrixAuthorizationStrategy must be classified as a security config");
        assertTrue(AuditSaveableListener.isSecurityConfiguration(new HudsonPrivateSecurityRealm()),
                "HudsonPrivateSecurityRealm must be classified as a security config");
        assertTrue(AuditSaveableListener.isSecurityConfiguration(new RoleBasedAuthorizationStrategy()),
                "RoleBasedAuthorizationStrategy must be classified as a security config");
        assertFalse(AuditSaveableListener.isSecurityConfiguration(new StandardGlobalConfig()),
                "StandardGlobalConfig must not be classified as a security config");
        assertFalse(AuditSaveableListener.isSecurityConfiguration(null),
                "null Saveable must return false");
    }
}
