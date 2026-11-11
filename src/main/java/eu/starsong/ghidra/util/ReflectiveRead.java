package eu.starsong.ghidra.util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Read a property of an object that may expose it as a method or as a field.
 *
 * <p>This exists because of a real regression: {@code BSimIngestService} read
 * {@code DescriptionManager.numFunctions} with {@code getField(...)}, and in the
 * BSim API that property is a <em>method</em> — so the read returned 0 and every
 * ingest failed with "no function with a body could be decompiled". The same
 * object has fields it does expose ({@code InsertResponse.numfunc}).
 *
 * <p>So the order is: a no-argument method of that name first, then a public
 * field. Both are reflective and both are failure-tolerant, because the BSim API
 * is internal and moves between Ghidra releases; a property that is not there is
 * reported as absent, never as a crash.
 */
public final class ReflectiveRead {

    private ReflectiveRead() {
    }

    /**
     * The value of {@code name} on {@code bean}, or null when it has neither a
     * no-argument method nor a public field of that name.
     */
    public static Object value(Object bean, String name) {
        if (bean == null || name == null || name.isEmpty()) {
            return null;
        }
        try {
            Method method = bean.getClass().getMethod(name);
            return method.invoke(bean);
        } catch (Throwable noMethod) {
            // Fall through to the field.
        }
        try {
            Field field = bean.getClass().getField(name);
            return field.get(bean);
        } catch (Throwable noField) {
            return null;
        }
    }

    /**
     * The value of {@code name} as an int, or {@code fallback} when it is absent
     * or is not a number.
     */
    public static int integer(Object bean, String name, int fallback) {
        Object value = value(bean, name);
        return value instanceof Number ? ((Number) value).intValue() : fallback;
    }

    /** The same, for a long. */
    public static long integer(Object bean, String name, long fallback) {
        Object value = value(bean, name);
        return value instanceof Number ? ((Number) value).longValue() : fallback;
    }

    /** The same, for a boolean; anything that is not a Boolean is the fallback. */
    public static boolean flag(Object bean, String name, boolean fallback) {
        Object value = value(bean, name);
        return value instanceof Boolean ? ((Boolean) value).booleanValue() : fallback;
    }

    /** The same, for a string; null stays null. */
    public static String text(Object bean, String name) {
        Object value = value(bean, name);
        return value == null ? null : String.valueOf(value);
    }
}