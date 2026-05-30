package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditScriptListenerClassificationTest {

    @Test
    void groovyHookScriptsAreClassifiedAsInitScripts() {
        String action = AuditScriptListener.resolveAction(
                jenkins.util.groovy.GroovyHookScript.class,
                "/var/jenkins_home/init.groovy.d/01-create-user.groovy");

        assertEquals(AuditScriptListener.INIT_SCRIPT_EXECUTED_ACTION, action);
        assertEquals("InitScript", AuditScriptListener.resolveTarget(jenkins.util.groovy.GroovyHookScript.class, action));
        assertTrue(AuditScriptListener.isInitScriptExecution(
                jenkins.util.groovy.GroovyHookScript.class,
                "/var/jenkins_home/init.groovy.d/01-create-user.groovy"));
    }
}