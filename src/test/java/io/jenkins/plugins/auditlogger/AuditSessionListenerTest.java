package io.jenkins.plugins.auditlogger;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.*;

public class AuditSessionListenerTest {

    @Test
    public void testSessionLifecycleAndAssociation() {
        AuditSessionListener listener = new AuditSessionListener();
        String sessionId = "test-session-12345";

        HttpSession mockSession = (HttpSession) Proxy.newProxyInstance(
                HttpSession.class.getClassLoader(),
                new Class<?>[]{HttpSession.class},
                (proxy, method, args) -> {
                    if ("getId".equals(method.getName())) {
                        return sessionId;
                    }
                    return null;
                }
        );

        HttpSessionEvent event = new HttpSessionEvent(mockSession);
        listener.sessionCreated(event);

        assertTrue(AuditSessionListener.getActiveSessionCount() > 0);
        assertNotNull(AuditSessionListener.getActiveSessions().get(sessionId));

        AuditSessionListener.associateUsernameWithSession(sessionId, "alice");
        assertEquals("alice", AuditSessionListener.getActiveSessions().get(sessionId).username);

        listener.sessionDestroyed(event);
        assertNull(AuditSessionListener.getActiveSessions().get(sessionId));
    }
}
