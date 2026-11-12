package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.connection.Profile;
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
 * <p>Legacy configuration accepts local H2 paths. A worker profile selects a
 * native remote backend without exposing its endpoint or mutating global config.
 */
public final class BSimService {

    /** The class that proves the BSim query engine is on this build's classpath. */
    private static final String BSim_MARKER = "ghidra.features.bsim.query.BSimServerInfo";

    /** System property naming the signature database. */
    public static final String PROPERTY_DATABASE = "ghidra.bsim.database";

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

    /** A safe database identity: selected profile ID, or a legacy local path. */
    public static String database() {
        Profile profile = ConnectionProfiles.currentBsim();
        if (profile != null) {
            return profile.id();
        }
        String property = System.getProperty(PROPERTY_DATABASE);
        String configured = property != null && !property.isBlank()
            ? property : System.getenv(ENV_DATABASE);
        return configured == null || configured.isBlank() ? null
            : localPath(configured.trim());
    }

    /** Legacy configuration is a local path only; native URLs require profiles. */
    static String localPath(String value) {
        boolean windowsDrive = value.matches("^[A-Za-z]:[\\\\/].*");
        if (!windowsDrive && value.matches("^[A-Za-z][A-Za-z0-9+.-]*:.*")) {
            throw new IllegalArgumentException(
                "legacy BSim configuration accepts local paths only; use a worker profile");
        }
        return value;
    }

    static boolean remote() {
        Profile profile = ConnectionProfiles.currentBsim();
        return profile != null && !"h2".equals(profile.backend());
    }

    /** Internal H2 path, never a remote endpoint. */
    static String localDatabase(String database) {
        Profile profile = ConnectionProfiles.currentBsim();
        return profile == null ? localPath(database) : profile.endpoint();
    }

    /**
     * Whether a query may attempt to open this database. Remote existence is
     * established by native initialize(), never by probing the worker filesystem.
     */
    public static boolean databaseExists() {
        String configured = database();
        return configured != null
            && (remote() || BSimDatabase.exists(localDatabase(configured)));
    }

    /** Safe configuration status; remote status does not connect or expose URLs. */
    public static Map<String, Object> status() {
        Map<String, Object> data = new LinkedHashMap<>();
        boolean available = available();
        String configured = database();
        Profile profile = ConnectionProfiles.currentBsim();
        boolean remote = remote();
        boolean exists = configured != null && databaseExists();
        boolean query = profile == null || profile.permissions().contains("query");
        boolean ingest = profile == null || profile.permissions().contains("ingest");
        data.put("available", available);
        data.put("database", configured);
        data.put("profile", profile == null ? null : profile.id());
        data.put("backend", profile == null ? "h2" : profile.backend());
        data.put("database_exists", remote ? null : exists);
        data.put("connection_checked", false);
        data.put("ready", available && configured != null && query);
        data.put("can_ingest", available && configured != null && ingest);
        if (!available) {
            data.put("reason", "this Ghidra build has no BSim query engine");
        } else if (configured == null) {
            data.put("reason", "no signature database is configured; select a worker "
                + "profile or configure a local H2 path");
        } else if (!query) {
            data.put("reason", "the selected profile does not grant query permission");
        } else if (remote) {
            data.put("reason", "remote database availability is checked when an operation opens it");
        } else if (!exists) {
            data.put("reason", "the local signature database does not exist; ingest a program first");
        } else {
            data.put("reason", null);
        }
        return data;
    }
}