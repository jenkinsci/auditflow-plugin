package io.jenkins.plugins.auditlogger;

import hudson.Extension;
import jenkins.model.Jenkins;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.html.HtmlPage;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.junit.jupiter.api.Test;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.kohsuke.stapler.verb.GET;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditStaplerSurfaceRegressionTest {

    @Test
    void managementLinkDoesNotExposeEntriesGetter() {
        assertThrows(NoSuchMethodException.class, () -> AuditLoggerManagementLink.class.getMethod("getEntries"));
    }

    @Test
    void readOnlyEndpointsDeclareGetVerb() throws Exception {
        assertTrue(AuditLogRestApi.class
                .getMethod("doApi", StaplerRequest2.class, StaplerResponse2.class)
                .isAnnotationPresent(GET.class));
        assertTrue(AuditLoggerManagementLink.class
                .getMethod("doAlerts", StaplerRequest2.class, StaplerResponse2.class)
                .isAnnotationPresent(GET.class));
    }

    @Test
    void initializerOnlyHooksAreNotRegisteredAsExtensions() {
        assertFalse(AuditRequestCapture.class.isAnnotationPresent(Extension.class));
        assertFalse(AuditSessionListenerInitializer.class.isAnnotationPresent(Extension.class));
    }

    @Test
    void rootApiRequiresAdminPermission(JenkinsRule j) {
        enableAnonymousReadOnlySecurity(j);

        JenkinsRule.WebClient webClient = j.createWebClient();
        FailingHttpStatusCodeException failure = assertThrows(FailingHttpStatusCodeException.class,
                () -> webClient.goTo("auditflow/api", "application/json"));

        assertEquals(403, failure.getStatusCode());
    }

    @Test
    void alertsEndpointRequiresAdminPermission(JenkinsRule j) {
        enableAnonymousReadOnlySecurity(j);

        JenkinsRule.WebClient webClient = j.createWebClient();
        FailingHttpStatusCodeException failure = assertThrows(FailingHttpStatusCodeException.class,
                () -> webClient.goTo("manage/auditflow-logs/alerts", "application/json"));

        assertEquals(403, failure.getStatusCode());
    }

    @Test
    void managementPageOnlyShowsDismissActionForAnomalies(JenkinsRule j) throws Exception {
        JenkinsRule.WebClient webClient = j.createWebClient();
        webClient.getOptions().setJavaScriptEnabled(false);

        HtmlPage page = webClient.goTo("manage/auditflow-logs");

        assertNull(page.getElementById("btnInvestigate"));
        assertNotNull(page.getElementById("btnDismiss"));
    }

    private static void enableAnonymousReadOnlySecurity(JenkinsRule j) {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.READ)
                .everywhere()
                .toEveryone());
    }
}