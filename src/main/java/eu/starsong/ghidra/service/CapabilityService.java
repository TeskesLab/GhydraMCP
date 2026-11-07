package eu.starsong.ghidra.service;

import eu.starsong.ghidra.api.ApiConstants;
import eu.starsong.ghidra.resource.DevResource;
import eu.starsong.ghidra.resource.ScriptResource;
import eu.starsong.ghidra.server.GhidraContext;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Describes what one instance can do, for capability negotiation.
 *
 * <p>The bridge used to check {@code API_VERSION} by exact equality against a
 * bare {@code /plugin-version} answer, and a mismatch surfaced much later as a
 * generic "No active Ghidra instance". This is the machine-readable answer to
 * "what are you, and what do you support?": versions, the runtime, the feature
 * flags actually in effect, and the limits a client has to respect.
 *
 * <p>Only system properties and the request context are read here — no Ghidra
 * DB traversal — so this needs no EDT wrapping and no transaction.
 */
public final class CapabilityService {

    private CapabilityService() {
    }

    /** The capability payload served by {@code GET /capabilities}. */
    public static Map<String, Object> describe(GhidraContext ctx) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("plugin_version", ApiConstants.PLUGIN_VERSION);
        data.put("api_version", ApiConstants.API_VERSION);
        data.put("ghidra_version", ghidraVersion());
        data.put("java_version", System.getProperty("java.version", "unknown"));
        data.put("java_feature", Runtime.version().feature());
        data.put("headless", ctx.isHeadless());
        data.put("port", ctx.port());

        Map<String, Object> ports = new LinkedHashMap<>();
        ports.put("first", ApiConstants.DEFAULT_PORT);
        ports.put("last", ApiConstants.DEFAULT_PORT + ApiConstants.MAX_PORT_ATTEMPTS - 1);
        data.put("port_range", ports);

        Map<String, Object> features = new LinkedHashMap<>();
        features.put("scripts", ScriptResource.scriptsEnabled());
        features.put("dev_shutdown", DevResource.shutdownEnabled());
        features.put("decompiler", true);
        features.put("raw_image", true);
        features.put("inspect_address", true);
        features.put("batch_decompile", true);
        features.put("call_path", true);
        features.put("xrefs_by_name", true);
        features.put("ui_cursor", !ctx.isHeadless());
        features.put("capabilities", true);
        data.put("features", features);

        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("max_batch_targets", 200);
        limits.put("max_port_attempts", ApiConstants.MAX_PORT_ATTEMPTS);
        limits.put("read_timeout_seconds", intProperty("ghidra.mcp.read.timeout", 900));
        data.put("limits", limits);
        return data;
    }

    /**
     * Ghidra's own version, resolved reflectively so the plugin compiles against
     * both 11.x and 12.x without pinning one distribution's class layout.
     */
    private static String ghidraVersion() {
        try {
            Class<?> application = Class.forName("ghidra.framework.Application");
            Object version = application.getMethod("getApplicationVersion").invoke(null);
            return String.valueOf(version);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return System.getProperty("ghidra.version", "unknown");
        }
    }

    private static int intProperty(String name, int fallback) {
        String value = System.getProperty(name);
        if (value == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
