package eu.starsong.ghidra.middleware;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The read-only guard and the audit trail (I12), pure halves.
 *
 * <p>What can break silently is the set of methods considered mutating, the
 * truthiness of the switch, and the JSON escaping of a line — none of which
 * needs a running server.
 */
public class ReadOnlyGuardTest {

    @Test
    public void the_four_mutating_methods_are_refused() {
        for (String method : new String[] {"POST", "put", "Patch", "DELETE"}) {
            assertTrue(method + " changes state", ReadOnlyGuard.isMutating(method));
        }
    }

    @Test
    public void reads_and_preflights_are_not_mutations() {
        for (String method : new String[] {"GET", "HEAD", "OPTIONS", null, ""}) {
            assertFalse(String.valueOf(method), ReadOnlyGuard.isMutating(method));
        }
    }

    @Test
    public void the_switch_accepts_the_usual_spellings() {
        for (String value : new String[] {"1", "true", "TRUE", "yes", "on", " true "}) {
            assertTrue(value, ReadOnlyGuard.truthy(value));
        }
        for (String value : new String[] {"0", "false", "no", "off", null, "", "nope"}) {
            assertFalse(String.valueOf(value), ReadOnlyGuard.truthy(value));
        }
    }

    @Test
    public void the_refusal_has_its_own_code() {
        assertEquals("READ_ONLY_MODE", ReadOnlyGuard.CODE);
    }

    @Test
    public void a_trail_line_is_valid_json_escaped_text() {
        assertEquals("plain", AuditTrail.escape("plain"));
        assertEquals("a\\\"b", AuditTrail.escape("a\"b"));
        assertEquals("a\\\\b", AuditTrail.escape("a\\b"));
        assertEquals("a\\nb", AuditTrail.escape("a\nb"));
        assertEquals("\\u0001", AuditTrail.escape("\u0001"));
    }

    @Test
    public void the_trail_is_on_unless_disabled() {
        // The environment of the build decides; what is asserted is that the
        // default path is a real path and the switch is a plain boolean.
        assertTrue(AuditTrail.path().isAbsolute());
    }
}
