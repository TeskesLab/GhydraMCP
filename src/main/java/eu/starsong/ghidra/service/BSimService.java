package eu.starsong.ghidra.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What this Ghidra build can do with BSim (R1, discovery half).
 *
 * <p>BSim is a Ghidra feature, not a plugin API: the signature engine lives in
 * {@code ghidra.features.bsim.query}, and a build may ship without the feature
 * or with a different database backend. So availability is **discovered by
 * loading the class**, never assumed from the Ghidra version — the same rule the
 * capability negotiation uses for every optional feature.
 *
 * <p>The database location is configuration, not discovery: a mission needs to
 * know *which* database a query would read, and a runbook needs it to be stable.
 * It comes from {@code -Dghydra.bsim.database} or {@code GHYDRA_BSIM_DATABASE};
 * when neither is set the answer says so instead of pretending a query would
 * work.
 */
public final class BSimService {

    /** The class that proves the BSim query engine is on this build's classpath. */
    private static final String BSim_MARKER = "ghidra.features.bsim.query.BSimServerInfo";

    /** System property naming the signature database. */
    public static final String PROPERTY_DATABASE = "ghydra.bsim.database";

    /** Environment variable naming the signature database. */
    public static final String ENV_DATABASE = "GHYDRA_BSIM_DATABASE";

    private BSimService() {
    }

    /** Is the BSim query engine present in this Ghidra build? */
    public static boolean available() {
        try {
            Class.forName(BSim_MARKER);
            return true;
        } catch (Throwable missing) {
            // NoClassDefFoundError is an Error, and a build without the feature
            // is a normal state, not a failure of the plugin.
            return false;
        }
    }

    /** The configured database path, or null when none is configured. */
    public static String database() {
        String property = System.getProperty(PROPERTY_DATABASE);
        if (property != null && !property.isBlank()) {
            return property.trim();
        }
        String environment = System.getenv(ENV_DATABASE);
        if (environment != null && !environment.isBlank()) {
            return environment.trim();
        }
        return null;
    }

    /**
     * Is the configured database on disk?
     *
     * <p>An H2 database is not the path that names it: the file is
     * {@code <path>.mv.db} (older builds used {@code .h2.db}). Measured: a
     * 120 KB database created by an ingest was reported as "does not exist"
     * because only the bare path was checked — so every suffix H2 can use is
     * checked, and the bare path too, for a path that is a file already.
     */
    public static boolean databaseExists() {
        String configured = database();
        if (configured == null) {
            return false;
        }
        for (String suffix : new String[] { ".mv.db", ".h2.db", "" }) {
            try {
                Path path = Paths.get(configured + suffix);
                if (Files.exists(path)) {
                    return true;
                }
            } catch (RuntimeException invalid) {
                // A path the platform cannot express is "not there".
            }
        }
        return false;
    }

    /**
     * The whole answer, in one payload.
     *
     * <p>{@code ready} is the only field a client should branch on: it is true
     * only when the engine is present *and* a database is configured, and
     * {@code reason} says what is missing otherwise.
     */
    public static Map<String, Object> status() {
        Map<String, Object> data = new LinkedHashMap<>();
        boolean available = available();
        String configured = database();
        boolean exists = available && configured != null && databaseExists();
        data.put("available", available);
        data.put("database", configured);
        data.put("database_exists", exists);
        data.put("ready", available && configured != null);
        // Ingest creates the database when it does not exist yet, so it needs
        // only the engine and a name; a query needs the file on disk.
        data.put("can_ingest", available && configured != null);
        if (!available) {
            data.put("reason", "this Ghidra build has no BSim query engine "
                + "(" + BSim_MARKER + " is not on the classpath)");
        } else if (configured == null) {
            data.put("reason", "no signature database is configured; set -D"
                + PROPERTY_DATABASE + "=<path> or " + ENV_DATABASE + "=<path>");
        } else if (!exists) {
            data.put("reason", "the configured signature database does not exist: "
                + configured);
        } else {
            data.put("reason", null);
        }
        return data;
    }
}