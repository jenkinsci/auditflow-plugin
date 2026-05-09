package io.jenkins.plugins.auditlogger;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class AuditRequestCapturePluginRouteRegressionTest {

    @Test
    public void classifyPluginActionRecognizesModernPluginRoutes() {
        assertEquals("PLUGIN_REMOVED", AuditRequestCapture.classifyPluginAction("/plugin/greenballs/doUninstall"));
        assertEquals("PLUGIN_DISABLED", AuditRequestCapture.classifyPluginAction("/plugin/greenballs/makeDisabled"));
        assertEquals("PLUGIN_ENABLED", AuditRequestCapture.classifyPluginAction("/plugin/greenballs/makeEnabled"));
    }

    @Test
    public void classifyPluginActionStillRecognizesLegacyPluginManagerRoutes() {
        assertEquals("PLUGIN_REMOVED", AuditRequestCapture.classifyPluginAction("/pluginManager/plugin/git/uninstall"));
        assertEquals("PLUGIN_DISABLED", AuditRequestCapture.classifyPluginAction("/pluginManager/plugin/git/makeDisabled"));
        assertEquals("PLUGIN_ENABLED", AuditRequestCapture.classifyPluginAction("/pluginManager/plugin/git/makeEnabled"));
    }

    @Test
    public void extractPluginNameFromModernRoutesUsesPluginSegment() {
        assertEquals("greenballs", AuditRequestCapture.extractPluginNameFromUri("/plugin/greenballs/doUninstall"));
        assertEquals("greenballs", AuditRequestCapture.extractPluginNameFromUri("/plugin/greenballs/makeDisabled"));
    }

    @Test
    public void installAndUpdateUriHelpersStayNarrow() {
        assertTrue(AuditRequestCapture.isPluginInstallUri("/pluginManager/uploadPlugin"));
        assertTrue(AuditRequestCapture.isPluginUpdateUri("/pluginManager/update"));
        assertTrue(AuditRequestCapture.isPluginUpdateUri("/manage/pluginManager/deploy"));
        assertFalse(AuditRequestCapture.isPluginUpdateUri("/manage/pluginManager/updates/"));
        assertNull(AuditRequestCapture.classifyPluginAction("/plugin/greenballs/images/24x24/ball.png"));
    }

    @Test
    public void scriptConsoleMatcherRecognizesManageRoutesWithoutBroadeningTooFar() {
        assertTrue(RouteAwareUrlMatcher.isScriptConsoleAccess("/script"));
        assertTrue(RouteAwareUrlMatcher.isScriptConsoleAccess("/manage/script"));
        assertTrue(RouteAwareUrlMatcher.isScriptConsoleAccess("/scriptText"));
        assertTrue(RouteAwareUrlMatcher.isScriptConsoleAccess("/manage/scriptText"));
        assertFalse(RouteAwareUrlMatcher.isScriptConsoleAccess("/manage/script/console"));
        assertFalse(RouteAwareUrlMatcher.isScriptConsoleAccess("/manage/configure/script"));
    }
}