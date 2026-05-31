package io.jenkins.plugins.auditlogger;

import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.junit.jupiter.api.Test;
import jenkins.model.Jenkins;
import org.htmlunit.Page;

import java.lang.reflect.Field;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class CoverageFixesTest {

    @Test
    void testAnomalyDetectorBruteForce() {
        AnomalyDetector detector = new AnomalyDetector();
        
        // Trigger 4 failures - no alert
        for (int i = 0; i < 4; i++) {
            detector.analyze(new AuditLogEntry("test_user", "FAILED_LOGIN", "target", "details", System.currentTimeMillis()));
        }
        assertTrue(detector.getAlerts(10).isEmpty());
        
        // 5th failure triggers alert
        detector.analyze(new AuditLogEntry("test_user", "FAILED_LOGIN", "target", "details", System.currentTimeMillis()));
        assertTrue(!detector.getAlerts(10).isEmpty());
        assertTrue(detector.getAlerts(10).get(0).type == AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN);
    }

    @Test
    void testAuditLogRestApiAlertsIncluded(JenkinsRule j) throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .toEveryone());
        
        // Ensure API is enabled
        AuditLoggerConfiguration.get().setEnableAuditApi(true);

        // Feed enough events to trigger anomaly alert in the singleton storage
        for (int i = 0; i < 5; i++) {
            AuditLogStorage.getInstance().addEntry(new AuditLogEntry("hacker", "FAILED_LOGIN", "tgt", "details", System.currentTimeMillis()));
        }
        
        // Call API
        JenkinsRule.WebClient webClient = j.createWebClient();
        Page page = webClient.goTo("auditflow/api", "application/json");
        String content = page.getWebResponse().getContentAsString();
        
        // Verify anomalies JSON is present and populated
        assertTrue(content.contains("anomalies"));
        assertTrue(content.contains("BRUTE_FORCE_LOGIN"));
        assertTrue(content.contains("hacker"));
    }

    @Test
    void testAuditLogStorageExceptionCaught() throws Exception {
        // Inject an anonymous anomaly detector that throws an exception
        AnomalyDetector mockDetector = new AnomalyDetector() {
            @Override
            public void analyze(AuditLogEntry entry) {
                throw new RuntimeException("Simulated exception");
            }
        };
        
        AuditLogStorage storage = AuditLogStorage.getInstance();
        Field detectorField = AuditLogStorage.class.getDeclaredField("anomalyDetector");
        detectorField.setAccessible(true);
        AnomalyDetector original = (AnomalyDetector) detectorField.get(storage);
        
        try {
            detectorField.set(storage, mockDetector);
            
            // This should not throw; the exception should be caught in addEntry
            storage.addEntry(new AuditLogEntry("user", "action", "target", "details", 0L));
            
        } finally {
            // Restore original detector
            detectorField.set(storage, original);
        }
    }
}
