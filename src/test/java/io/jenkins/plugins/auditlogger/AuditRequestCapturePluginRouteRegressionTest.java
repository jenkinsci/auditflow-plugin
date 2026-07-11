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
    void extractPluginTargetFromAdvancedUploadAndUrlBodies() {
        String multipartUploadBody = """
                ------WebKitFormBoundary
                Content-Disposition: form-data; name="name"; filename="git-client.hpi"
                Content-Type: application/octet-stream

                binary
                ------WebKitFormBoundary--
                """;
        String multipartUrlBody = """
                ------WebKitFormBoundary
                Content-Disposition: form-data; name="pluginUrl"

                https://updates.jenkins.io/download/plugins/mailer/489.vd4b_25144138f/mailer.hpi
                ------WebKitFormBoundary--
                """;
        String formBody = "pluginUrl=https%3A%2F%2Fupdates.jenkins.io%2Fdownload%2Fplugins%2Fgit%2F5.8.0%2Fgit.hpi";

        assertEquals("git-client", AuditRequestCapture.extractPluginTargetFromRequestBody(multipartUploadBody));
        assertEquals("mailer", AuditRequestCapture.extractPluginTargetFromRequestBody(multipartUrlBody));
        assertEquals("git", AuditRequestCapture.extractPluginTargetFromRequestBody(formBody));
    }

    @Test
    void normalizePluginTargetStripsVersionsPathsAndExtensions() {
        assertEquals("git", AuditRequestCapture.normalizePluginTarget("git@5.8.0"));
        assertEquals("mailer", AuditRequestCapture.normalizePluginTarget("https://updates.jenkins.io/download/plugins/mailer/489.vd4b_25144138f/mailer.hpi"));
        assertEquals("credentials", AuditRequestCapture.normalizePluginTarget("C:/temp/credentials.jpi"));
        assertEquals("git, mailer", AuditRequestCapture.normalizePluginTarget("git@5.8.0, mailer.hpi"));
    }

    @Test
    void installClassificationPromotesAlreadyInstalledPluginsToUpdated() {
        assertEquals("PLUGIN_UPDATED",
                AuditRequestCapture.resolvePluginAction("PLUGIN_INSTALLED", "git", "git"::equals));
        assertEquals("PLUGIN_INSTALLED",
                AuditRequestCapture.resolvePluginAction("PLUGIN_INSTALLED", "mailer", "git"::equals));
        assertEquals("PLUGIN_INSTALLED",
                AuditRequestCapture.resolvePluginAction("PLUGIN_INSTALLED", "git, mailer", "git"::equals));
        assertEquals("PLUGIN_UPDATED",
                AuditRequestCapture.resolvePluginAction("PLUGIN_UPDATED", "git", plugin -> false));
    }

    @Test
    void pluginActionDetailsUsePluralForMultipleTargets() {
        assertEquals("Plugin installed: git by admin",
                AuditRequestCapture.formatPluginActionDetails("PLUGIN_INSTALLED", "git", "admin"));
        assertEquals("Plugins installed: git, mailer by admin",
                AuditRequestCapture.formatPluginActionDetails("PLUGIN_INSTALLED", "git, mailer", "admin"));
        assertEquals("Plugins updated: git, mailer by admin",
                AuditRequestCapture.formatPluginActionDetails("PLUGIN_UPDATED", "git, mailer", "admin"));
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
        assertTrue(RouteAwareUrlMatcher.isRestartAction("/restart"));
        assertTrue(RouteAwareUrlMatcher.isRestartAction("/manage/restart"));
        assertFalse(RouteAwareUrlMatcher.isRestartAction("/updateCenter/restartStatus"));
    }

}
