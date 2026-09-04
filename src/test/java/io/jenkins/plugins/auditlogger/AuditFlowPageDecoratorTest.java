package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class AuditFlowPageDecoratorTest {

    private AuditFlowPageDecorator decorator;

    @BeforeEach
    void setUp() throws Exception {
        decorator = new AuditFlowPageDecorator();
        RequestHolder.clear();
        AuditLogStorage.clearInstance();
        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        Field startupTimeField = StartupPhaseManager.class.getDeclaredField("startupTime");
        startupTimeField.setAccessible(true);
        startupTimeField.set(null, 1L);
    }

    @AfterEach
    void tearDown() {
        RequestHolder.clear();
        try {
            AuditLogStorage.getInstance().shutdown();
        } catch (RuntimeException ignored) {}
        AuditLogStorage.clearInstance();
    }

    @Test
    void testBannerHiddenWhenNoAnomaliesExist(JenkinsRule j) {
        assertFalse(decorator.isBannerVisible(), "Banner should be hidden when 0 anomalies exist");
        assertEquals(0, decorator.getActiveAlertCount(), "Active alert count should be 0");
    }

    @Test
    void testBannerVisibleWhenAnomaliesExist(JenkinsRule j) {
        AuditLogStorage storage = AuditLogStorage.getInstance();
        AnomalyDetector detector = storage.getAnomalyDetector();

        // Inject simulated anomaly alert
        AnomalyDetector.AnomalyAlert alert = new AnomalyDetector.AnomalyAlert(
                AnomalyDetector.AnomalyType.BRUTE_FORCE_LOGIN,
                "target-user",
                "Multiple failed login attempts detected",
                "CRITICAL"
        );
        detector.addAlert(alert);

        assertTrue(decorator.isBannerVisible(), "Banner should be visible when active anomaly exists");
        assertTrue(decorator.getActiveAlertCount() > 0, "Active alert count should be > 0");
        assertEquals("CRITICAL", decorator.getHighestSeverity(), "Highest severity should match CRITICAL");

        // Verify dismissal hides the banner
        detector.dismissAllAlerts();
        assertFalse(decorator.isBannerVisible(), "Banner should hide after all alerts are dismissed");
        assertEquals(0, decorator.getActiveAlertCount(), "Active alert count should return 0 after dismissal");
    }

    @Test
    void testAuditFlowUrlFormat(JenkinsRule j) {
        String url = decorator.getAuditFlowUrl();
        assertNotNull(url, "AuditFlow URL should not be null");
        assertTrue(url.contains("manage/auditflow-logs/"), "URL should point to manage/auditflow-logs/");
    }
}
