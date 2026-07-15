package io.jenkins.plugins.auditlogger;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@WithJenkins
class AuditRequestCaptureRestartRegressionTest {

    @AfterEach
    void cleanup() {
        RequestHolder.clear();
        try {
            AuditLogStorage.getInstance().shutdown();
        } catch (RuntimeException ignored) {
            // Best-effort cleanup for isolated test storage.
        }
        AuditLogStorage.clearInstance();
    }

    @Test
    void captureRestartActionLogsUpdateCenterSafeRestartOnce(JenkinsRule j) {
        AuditLogStorage storage = AuditLogStorage.getInstance();
        storage.initialize();

        HttpServletRequest request = fakeRequest("POST", "/updateCenter/safeRestart");

        AuditRequestCapture.captureRestartAction(request, "harry");
        AuditRequestCapture.captureRestartAction(request, "harry");

        List<AuditLogEntry> restartEntries = storage.getAllEntries().stream()
                .filter(entry -> "SYSTEM_RESTART".equals(entry.getAction()))
                .toList();

        assertEquals(1, restartEntries.size());
        assertEquals("harry", restartEntries.get(0).getUsername());
        assertEquals("Jenkins", restartEntries.get(0).getTarget());
        assertEquals("CRITICAL", restartEntries.get(0).getSeverity());
        assertEquals("Safe restart initiated by harry", restartEntries.get(0).getDetails());
    }

    private static HttpServletRequest fakeRequest(String method, String requestUri) {
        Map<String, Object> attributes = new HashMap<>();
        return (HttpServletRequest) Proxy.newProxyInstance(
                AuditRequestCaptureRestartRegressionTest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, invokedMethod, args) -> {
                    String name = invokedMethod.getName();
                    switch (name) {
                        case "getMethod":
                            return method;
                        case "getRequestURI":
                            return requestUri;
                        case "getContextPath":
                            return "";
                        case "getAttribute":
                            return attributes.get(args[0]);
                        case "setAttribute":
                            attributes.put((String) args[0], args[1]);
                            return null;
                        case "getSession":
                            return null;
                        case "getRemoteUser":
                            return null;
                        case "getUserPrincipal":
                            return null;
                        case "removeAttribute":
                            attributes.remove(args[0]);
                            return null;
                        case "hashCode":
                            return System.identityHashCode(proxy);
                        case "equals":
                            return proxy == args[0];
                        case "toString":
                            return "FakeHttpServletRequest[" + method + " " + requestUri + "]";
                        default:
                            Class<?> returnType = invokedMethod.getReturnType();
                            if (returnType == boolean.class) {
                                return false;
                            }
                            if (returnType == int.class) {
                                return 0;
                            }
                            if (returnType == long.class) {
                                return 0L;
                            }
                            return null;
                    }
                });
    }
}
