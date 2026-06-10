package io.jenkins.plugins.auditlogger;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import net.sf.json.JSONObject;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.htmlunit.util.NameValuePair;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AuditScriptListenerTest {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule j) throws Exception {
        this.j = j;
        AuditLoggerConfiguration configuration = j.getInstance().getExtensionList(AuditLoggerConfiguration.class).get(0);
        JSONObject json = new JSONObject();
        json.put("enableSystemConfigEvents", true);
        configuration.configure((org.kohsuke.stapler.StaplerRequest2) null, json);
    }

    @Test
    void scriptTextExecutionIsAuditedFromScriptListener() throws Exception {
        long startTime = System.currentTimeMillis();
        JenkinsRule.WebClient webClient = j.createWebClient();
        JSONObject crumb = JSONObject.fromObject(
                webClient.goTo("crumbIssuer/api/json", "application/json")
                        .getWebResponse()
                        .getContentAsString(StandardCharsets.UTF_8));

        WebRequest request = new WebRequest(new URL(j.getURL(), "scriptText"), HttpMethod.POST);
        request.setAdditionalHeader(crumb.getString("crumbRequestField"), crumb.getString("crumb"));
        request.setRequestParameters(List.of(
                new NameValuePair("script", "println('listener path')")));

        Page page = webClient.getPage(request);
        String response = page.getWebResponse().getContentAsString(StandardCharsets.UTF_8);

        List<AuditLogEntry> entries = AuditLogStorage.getInstance().filterEntries(
            null, AuditScriptListener.SCRIPT_CONSOLE_ACCESS_ACTION, startTime, null);
        AuditLogEntry latest = entries.get(entries.size() - 1);

        assertTrue(response.contains("listener path"));
        assertFalse(entries.isEmpty());
        assertEquals(AuditScriptListener.SCRIPT_CONSOLE_ACCESS_ACTION, latest.getAction());
        assertEquals("ScriptConsole", latest.getTarget());
        assertTrue(latest.getDetails().contains("println('listener path')"));
        assertTrue(latest.getDetails().contains("hudson.util.RemotingDiagnostics"));
    }
}