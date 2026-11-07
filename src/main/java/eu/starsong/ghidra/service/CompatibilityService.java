package eu.starsong.ghidra.service;

import ghidra.util.Msg;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Detects whether the running Ghidra matches the series this extension was
 * compiled against, by probing the signatures of the APIs that moved.
 *
 * <p>The committed {@code lib/*.jar} are 12.0.1, so a bare build calls
 * {@code DataTypeComponent.setFieldName(String)} as {@code void}. Ghidra 12.2
 * changed that method's return type to {@code DataTypeComponent}; the return
 * type is part of the JVM method descriptor, so the call site fails at runtime
 * with {@code NoSuchMethodError}. The same happened to the
 * {@code DataTypeManager.remove} overloads. Reflection removes those
 * descriptors from our call sites, but a startup probe makes a mismatch visible
 * before a request hits one of them.
 *
 * <p>Nothing here references the changed classes at compile time: it loads them
 * by name and inspects them, so it works against 11.x, 12.0-12.1 and 12.2.
 */
public final class CompatibilityService {

    /** The series the committed lib/*.jar (and a bare mvn package) target. */
    public static final String COMPILED_AGAINST = "12.0.1";

    private static final String DATA_TYPE_COMPONENT =
        "ghidra.program.model.data.DataTypeComponent";
    private static final String DATA_TYPE_MANAGER =
        "ghidra.program.model.data.DataTypeManager";

    private CompatibilityService() {
    }

    /** A machine-readable compatibility report, also served by GET /capabilities. */
    public static Map<String, Object> report(String ghidraVersion) {
        Map<String, Object> data = new LinkedHashMap<>();
        String fieldReturn = returnTypeOf(DATA_TYPE_COMPONENT, "setFieldName", String.class);
        List<String> overloads = removeOverloads();
        boolean compatible = fieldReturn != null && !overloads.isEmpty();

        data.put("ghidra_version", ghidraVersion);
        data.put("compiled_against", COMPILED_AGAINST);
        data.put("set_field_name_return", fieldReturn == null ? "missing" : fieldReturn);
        data.put("remove_overloads", overloads);
        data.put("compatible", compatible);
        data.put("remedy", compatible ? "" :
            "Rebuild the extension with GHIDRA_HOME pointing at this installation and "
            + "-Dghidra.version=<its series>: the deployed jar must be compiled against "
            + "the Ghidra that loads it.");
        return data;
    }

    /** Log the detected series and the signatures once, when the server starts. */
    public static void logAtStartup() {
        Map<String, Object> r = report(CapabilityService.ghidraVersion());
        Msg.info(CompatibilityService.class,
            "GhydraMCP compatibility: Ghidra " + r.get("ghidra_version")
                + ", compiled against " + COMPILED_AGAINST
                + ", setFieldName returns " + r.get("set_field_name_return")
                + ", remove overloads " + r.get("remove_overloads")
                + ", compatible=" + r.get("compatible"));
        if (!Boolean.TRUE.equals(r.get("compatible"))) {
            Msg.warn(CompatibilityService.class,
                "GhydraMCP may have been compiled against a different Ghidra series: "
                    + r.get("remedy"));
        }
    }

    /** The simple name of a public method's return type, or null when absent. */
    static String returnTypeOf(String className, String methodName, Class<?>... params) {
        try {
            Class<?> type = Class.forName(className);
            return type.getMethod(methodName, params).getReturnType().getSimpleName();
        } catch (ClassNotFoundException | NoSuchMethodException | LinkageError e) {
            return null;
        }
    }

    private static List<String> removeOverloads() {
        List<String> found = new ArrayList<>();
        try {
            Class<?> manager = Class.forName(DATA_TYPE_MANAGER);
            for (Method method : manager.getMethods()) {
                if (!"remove".equals(method.getName())) {
                    continue;
                }
                Class<?>[] params = method.getParameterTypes();
                if (params.length == 1 && params[0].getName().endsWith("DataType")) {
                    found.add("remove(DataType)");
                } else if (params.length == 2 && params[0].getName().endsWith("DataType")) {
                    found.add("remove(DataType," + params[1].getSimpleName() + ")");
                }
            }
        } catch (ClassNotFoundException | LinkageError e) {
            // A missing class is itself a compatibility problem: report no overloads.
        }
        return found;
    }
}
