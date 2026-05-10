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
        AuditLoggerConfiguration configuration = AuditLoggerConfiguration.get();
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
                null, "SCRIPT_CONSOLE_ACCESS", startTime, null);
        AuditLogEntry latest = entries.get(entries.size() - 1);

        assertTrue(response.contains("listener path"));
        assertFalse(entries.isEmpty());
        assertEquals("SCRIPT_CONSOLE_ACCESS", latest.getAction());
        assertEquals("ScriptConsole", latest.getTarget());
        assertTrue(latest.getDetails().contains("println('listener path')"));
        assertTrue(latest.getDetails().contains("hudson.util.RemotingDiagnostics"));
    }
}