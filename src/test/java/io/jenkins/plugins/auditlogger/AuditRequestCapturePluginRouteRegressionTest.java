package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditRequestCapturePluginRouteRegressionTest {

    @Test
    void classifyPluginActionRecognizesModernPluginRoutes() {
        assertEquals("PLUGIN_REMOVED", AuditRequestCapture.classifyPluginAction("/plugin/greenballs/doUninstall"));
        assertEquals("PLUGIN_DISABLED", AuditRequestCapture.classifyPluginAction("/plugin/greenballs/makeDisabled"));
        assertEquals("PLUGIN_ENABLED", AuditRequestCapture.classifyPluginAction("/plugin/greenballs/makeEnabled"));
    }

    @Test
    void classifyPluginActionStillRecognizesLegacyPluginManagerRoutes() {
        assertEquals("PLUGIN_REMOVED", AuditRequestCapture.classifyPluginAction("/pluginManager/plugin/git/uninstall"));
        assertEquals("PLUGIN_DISABLED", AuditRequestCapture.classifyPluginAction("/pluginManager/plugin/git/makeDisabled"));
        assertEquals("PLUGIN_ENABLED", AuditRequestCapture.classifyPluginAction("/pluginManager/plugin/git/makeEnabled"));
    }

    @Test
    void extractPluginNameFromModernRoutesUsesPluginSegment() {
        assertEquals("greenballs", AuditRequestCapture.extractPluginNameFromUri("/plugin/greenballs/doUninstall"));
        assertEquals("greenballs", AuditRequestCapture.extractPluginNameFromUri("/plugin/greenballs/makeDisabled"));
    }

    @Test
    void installAndUpdateUriHelpersStayNarrow() {
        assertTrue(AuditRequestCapture.isPluginInstallUri("/pluginManager/install"));
        assertTrue(AuditRequestCapture.isPluginInstallUri("/pluginManager/installPlugins"));
        assertTrue(AuditRequestCapture.isPluginInstallUri("/pluginManager/uploadPlugin"));
        assertTrue(AuditRequestCapture.isPluginInstallUri("/pluginManager/installNecessaryPlugins"));
        assertTrue(AuditRequestCapture.isPluginUpdateUri("/pluginManager/update"));
        assertTrue(AuditRequestCapture.isPluginUpdateUri("/manage/pluginManager/deploy"));
        assertFalse(AuditRequestCapture.isPluginInstallUri("/pluginManager/installStatus"));
        assertFalse(AuditRequestCapture.isPluginInstallUri("/job/myplugins/install"));
        assertFalse(AuditRequestCapture.isPluginUpdateUri("/manage/pluginManager/updates/"));
        assertNull(AuditRequestCapture.classifyPluginAction("/pluginManager/installStatus"));
        assertNull(AuditRequestCapture.classifyPluginAction("/plugin/greenballs/images/24x24/ball.png"));
    }

    @Test
    void classifyPluginActionKeepsInstallAndUpdateRoutesDistinct() {
        assertEquals("PLUGIN_INSTALLED", AuditRequestCapture.classifyPluginAction("/pluginManager/install"));
        assertEquals("PLUGIN_INSTALLED", AuditRequestCapture.classifyPluginAction("/pluginManager/installPlugins"));
        assertEquals("PLUGIN_INSTALLED", AuditRequestCapture.classifyPluginAction("/pluginManager/installNecessaryPlugins"));
        assertEquals("PLUGIN_UPDATED", AuditRequestCapture.classifyPluginAction("/pluginManager/update"));
        assertEquals("PLUGIN_UPDATED", AuditRequestCapture.classifyPluginAction("/manage/pluginManager/deploy"));
    }

    @Test
    void extractPluginTargetFromJsonInstallBody() {
        assertEquals("git", AuditRequestCapture.extractPluginTargetFromJsonBody("{\"dynamicLoad\":true,\"plugins\":[\"git\"]}"));
        assertEquals("git, mailer", AuditRequestCapture.extractPluginTargetFromJsonBody("{\"dynamicLoad\":true,\"plugins\":[\"git\",\"mailer\"]}"));
        assertNull(AuditRequestCapture.extractPluginTargetFromJsonBody("{\"dynamicLoad\":true}"));
    }

    @Test
    void configurationMatcherAcceptsSecuritySubmitRoute() {
        assertTrue(RouteAwareUrlMatcher.isConfigurationChange("/configure"));
        assertTrue(RouteAwareUrlMatcher.isConfigurationChange("/manage/configureSecurity"));
        assertTrue(RouteAwareUrlMatcher.isConfigurationChange("/manage/configureSecurity/configure"));
        assertTrue(RouteAwareUrlMatcher.isConfigurationChange("/manage/configure"));
        assertFalse(RouteAwareUrlMatcher.isConfigurationChange("/manage/configureSecurity/warnings"));
    }

    @Test
    void restartMatcherAcceptsPostInstallUpdateCenterRoute() {
        assertTrue(RouteAwareUrlMatcher.isRestartAction("/updateCenter/safeRestart"));
        assertTrue(RouteAwareUrlMatcher.isRestartAction("/updateCenter/restart"));
        assertFalse(RouteAwareUrlMatcher.isRestartAction("/updateCenter/restartStatus"));
    }

}
