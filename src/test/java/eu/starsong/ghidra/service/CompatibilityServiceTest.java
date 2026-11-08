package eu.starsong.ghidra.service;

import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Pure-logic tests for the startup compatibility probe. No live Program and no
 * running Ghidra are needed: the probe only reflects on classes loaded by name.
 */
public class CompatibilityServiceTest {

    @Test
    public void reportHasTheExpectedShape() {
        Map<String, Object> report = CompatibilityService.report("12.1.2");
        assertEquals("12.1.2", report.get("ghidra_version"));
        assertEquals(CompatibilityService.COMPILED_AGAINST, report.get("compiled_against"));
        assertNotNull(report.get("set_field_name_return"));
        assertNotNull(report.get("remove_overloads"));
        assertNotNull(report.get("compatible"));
        assertNotNull(report.get("remedy"));
        assertTrue(report.get("compatible") instanceof Boolean);
    }

    @Test
    public void aMissingMethodIsReportedAsMissing() {
        assertNull(CompatibilityService.returnTypeOf(
            "java.lang.String", "thisMethodDoesNotExist", String.class));
    }

    @Test
    public void aKnownMethodReturnTypeIsDetected() {
        // A JDK class proves the reflection itself works, independent of which
        // Ghidra jars happen to be on the test classpath.
        assertEquals("int", CompatibilityService.returnTypeOf("java.lang.String", "length"));
    }

    @Test
    public void aMissingClassIsNotAnError() {
        assertNull(CompatibilityService.returnTypeOf(
            "no.such.Class", "whatever", String.class));
    }
}
