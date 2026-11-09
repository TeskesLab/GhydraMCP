package eu.starsong.ghidra.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * The regression that made every BSim ingest fail.
 *
 * <p>{@code DescriptionManager.numFunctions} is a method; reading it as a field
 * returned 0, so the ingest answered "no function with a body could be
 * decompiled". These tests pin the rule that makes the read safe: try the method
 * first, fall back to the field, and treat an absent property as absent.
 */
public class ReflectiveReadTest {

    /** A property exposed the way the BSim API exposes some of them: a method. */
    public static class MethodOnly {
        public int numFunctions() {
            return 94;
        }

        public String getName() {
            return "where.exe";
        }

        public boolean isTracked() {
            return true;
        }
    }

    /** A property exposed the way {@code InsertResponse} exposes some: a field. */
    public static class FieldOnly {
        public int numfunc = 94;
        public String name = "where.exe";
    }

    /** Both: the method has to win, because it is the live value. */
    public static class BothForms {
        public int numFunctions = 1;

        public int numFunctions() {
            return 94;
        }
    }

    @Test
    public void a_method_is_read_when_there_is_no_field() {
        assertEquals(94, ReflectiveRead.integer(new MethodOnly(), "numFunctions", 0));
    }

    @Test
    public void a_field_is_read_when_there_is_no_method() {
        assertEquals(94, ReflectiveRead.integer(new FieldOnly(), "numfunc", 0));
    }

    @Test
    public void the_method_wins_when_both_exist() {
        assertEquals(94, ReflectiveRead.integer(new BothForms(), "numFunctions", 0));
    }

    @Test
    public void an_absent_property_is_the_fallback_not_zero() {
        assertEquals(7, ReflectiveRead.integer(new MethodOnly(), "notThere", 7));
        assertNull(ReflectiveRead.value(new MethodOnly(), "notThere"));
    }

    @Test
    public void a_null_bean_is_absent_and_does_not_throw() {
        assertEquals(-1, ReflectiveRead.integer(null, "numFunctions", -1));
        assertNull(ReflectiveRead.value(null, "numFunctions"));
    }

    @Test
    public void a_value_of_the_wrong_type_is_the_fallback() {
        assertEquals(0, ReflectiveRead.integer(new MethodOnly(), "getName", 0));
        assertEquals("where.exe", ReflectiveRead.text(new MethodOnly(), "getName"));
        assertTrue(ReflectiveRead.flag(new MethodOnly(), "isTracked", false));
        assertFalse(ReflectiveRead.flag(new MethodOnly(), "getName", false));
    }

    @Test
    public void a_method_that_throws_is_absent_not_fatal() {
        Object bean = new Object() {
            public int explode() {
                throw new IllegalStateException("the API changed");
            }
        };
        assertEquals(3, ReflectiveRead.integer(bean, "explode", 3));
    }
}