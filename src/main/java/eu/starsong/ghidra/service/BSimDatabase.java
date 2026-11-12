package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.connection.Profile;
import eu.starsong.ghidra.connection.WorkerAuthentication;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;

/**
 * The pieces of BSim that ingest and query share: opening a database, finding
 * where a program lives, and cleaning up.
 *
 * <p>Everything is reflective for the reason {@link BSimIngestService} explains:
 * the API of {@code ghidra.features.bsim.query} is internal and has moved between
 * series, and the extension is built against 11.x <em>and</em> 12.x.
 *
 * <p>Two measurements live here so both services inherit them: an H2 database is
 * the file {@code <path>.mv.db} (not {@code <path>}), and {@code initialize()}
 * on a missing file answers "Database does not exist" instead of creating it.
 */
final class BSimDatabase {

    static final String SERVER_INFO = "ghidra.features.bsim.query.BSimServerInfo";
    static final String H2_DATABASE = "ghidra.features.bsim.query.file.H2FileFunctionDatabase";
    static final String CLIENT_FACTORY = "ghidra.features.bsim.query.BSimClientFactory";
    static final String GEN_SIGNATURES = "ghidra.features.bsim.query.GenSignatures";
    static final String FUNCTION_DATABASE = "ghidra.features.bsim.query.FunctionDatabase";
    static final String DATABASE_INFO =
        "ghidra.features.bsim.query.description.DatabaseInformation";
    static final String CREATE_DATABASE =
        "ghidra.features.bsim.query.protocol.CreateDatabase";
    static final String GHIDRA_URL = "ghidra.framework.protocol.ghidra.GhidraURL";

    /** The template Ghidra's own script uses for a general-purpose database. */
    static final String DEFAULT_TEMPLATE = "medium_nosize";

    private BSimDatabase() {
    }

    /** The class loader the extension was loaded with. */
    static ClassLoader loader() {
        return BSimDatabase.class.getClassLoader();
    }

    /** Is the H2 file (or any of its companions) on disk? */
    static boolean exists(String database) {
        for (String suffix : new String[] { ".mv.db", ".h2.db", "" }) {
            try {
                Path path = Paths.get(database + suffix);
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
     * Open the configured database, creating it first when asked and absent.
     *
     * @param database   the path that names the database
     * @param createWhenMissing whether a missing database is created
     * @param data       where the failure (or the {@code created} fact) is written
     * @return the connected database, or null after writing the failure
     */
    static Object open(String database, boolean createWhenMissing,
            Map<String, Object> data) {
        return open(database, createWhenMissing, false, data);
    }

    /**
     * The same, saying whether a database created here records the call graph.
     *
     * <p>The flag travels to {@code CreateDatabase}: claiming it in the payload
     * while creating the database with it off was a lie the report told.
     */
    static Object open(String database, boolean createWhenMissing,
            boolean trackCallGraph, Map<String, Object> data) {
        Object connection = null;
        boolean remote = BSimService.remote();
        String local = remote ? null : BSimService.localDatabase(database);
        try {
            ClassLoader loader = loader();
            Class<?> serverInfoClass = Class.forName(SERVER_INFO, true, loader);
            if (remote) {
                Profile profile = ConnectionProfiles.currentBsim();
                Object serverInfo = WorkerAuthentication.bsimServerInfo(profile);
                Class<?> factory = Class.forName(CLIENT_FACTORY, true, loader);
                connection = factory.getMethod("buildClient", serverInfoClass, boolean.class)
                    .invoke(null, serverInfo, false);
                // Remote provisioning is an administrator operation, never ingest.
                data.put("created", Boolean.FALSE);
            } else {
                if (!exists(local) && !createWhenMissing) {
                    failure(data, "BSIM_NO_DATABASE",
                        "the local signature database does not exist; ingest a program first");
                    return null;
                }
                Object serverInfo = serverInfoClass.getConstructor(String.class)
                    .newInstance(local);
                Class<?> h2Class = Class.forName(H2_DATABASE, true, loader);
                connection = h2Class.getConstructor(serverInfoClass).newInstance(serverInfo);
                boolean existed = exists(local);
                if (!existed) {
                    String created = create(connection, local, trackCallGraph);
                    if (created != null) {
                        release(connection, database);
                        failure(data, "BSIM_CREATE_FAILED", created);
                        return null;
                    }
                }
                data.put("created", !existed);
            }
            if (connection == null || !Boolean.TRUE.equals(
                    connection.getClass().getMethod("initialize").invoke(connection))) {
                release(connection, database);
                failure(data, "BSIM_INIT_FAILED",
                    remote ? "the remote signature database could not be opened; it must already exist"
                        : "the local signature database could not be opened");
                return null;
            }
            if (remote && "Unencrypted_No_Authentication".equals(
                    String.valueOf(call(connection, "getConnectionType")))) {
                release(connection, database);
                failure(data, "BSIM_INIT_FAILED",
                    "the remote signature database does not provide authenticated transport");
                return null;
            }
            return connection;
        } catch (Throwable failed) {
            release(connection, database);
            failure(data, "BSIM_INIT_FAILED", describe(unwrap(failed)));
            return null;
        }
    }

    /** Create the database with Ghidra's own {@code CreateDatabase} command. */
    private static String create(Object connection, String database,
            boolean trackCallGraph) {
        try {
            ClassLoader loader = loader();
            Class<?> infoClass = Class.forName(DATABASE_INFO, true, loader);
            Object info = infoClass.getConstructor().newInstance();
            infoClass.getField("databasename")
                .set(info, Paths.get(database).getFileName().toString());
            infoClass.getField("trackcallgraph").set(info,
                Boolean.valueOf(trackCallGraph));

            Class<?> commandClass = Class.forName(CREATE_DATABASE, true, loader);
            Object command = commandClass.getConstructor().newInstance();
            commandClass.getField("info").set(command, info);
            commandClass.getField("config_template").set(command, DEFAULT_TEMPLATE);
            Class<?> databaseClass = Class.forName(FUNCTION_DATABASE, true, loader);
            Object response = commandClass.getMethod("execute", databaseClass)
                .invoke(command, connection);
            if (response == null) {
                return "the database could not be created";
            }
            return null;
        } catch (Throwable failed) {
            return describe(unwrap(failed));
        }
    }

    /**
     * The repository and path BSim records for this program.
     *
     * <p>Taken from the program's own project file, the way Ghidra does it; a
     * program that was never saved has neither, and BSim is told so instead of
     * being handed a made-up path.
     */
    /**
     * The repository and path BSim records for this program, plus a reason when
     * they are unknown.
     *
     * <p>The third element is null on success and explains the absence otherwise:
     * an ingest of a program that was never saved used to report two nulls and
     * leave the reader to guess why.
     */
    static String[] projectLocation(Program program) {
        String[] location = new String[] { null, null, null };
        try {
            var domainFile = program.getDomainFile();
            URL fileUrl = domainFile.getSharedProjectURL(null);
            if (fileUrl == null) fileUrl = domainFile.getLocalProjectURL(null);
            if (fileUrl == null) {
                location[2] = "the program has not been saved to a project, so "
                    + "BSim cannot record a repository and a path for it";
                return location;
            }
            Class<?> ghidraUrl = Class.forName(GHIDRA_URL);
            String pathname = (String) ghidraUrl.getMethod("getProjectPathname", URL.class)
                .invoke(null, fileUrl);
            if (pathname != null) {
                int lastSlash = pathname.lastIndexOf('/');
                // BSim appends the program name to the path, so it is removed.
                location[1] = lastSlash <= 0 ? "/" : pathname.substring(0, lastSlash);
            }
            URL projectUrl = (URL) ghidraUrl.getMethod("getProjectURL", URL.class)
                .invoke(null, fileUrl);
            location[0] = projectUrl == null ? null : projectUrl.toExternalForm();
        } catch (Throwable ignored) {
            // Nothing was saved: BSim gets the nulls and records less metadata.
        }
        return location;
    }

    /** Add a {@code List} field of the database configuration to a generator. */
    static void addList(Object generator, Object databaseInfo, String method,
            String field) {
        try {
            Object value = databaseInfo.getClass().getField(field).get(databaseInfo);
            if (value instanceof List && !((List<?>) value).isEmpty()) {
                generator.getClass().getMethod(method, List.class)
                    .invoke(generator, value);
            }
        } catch (Throwable ignored) {
            // The database does not carry this list; nothing to add.
        }
    }

    /**
     * Close a database and dispose the shared data source it created.
     *
     * <p>Ghidra's own script does exactly this ("Dispose database source if it did
     * not previously exist"): {@code close()} alone leaves the H2 pool in the
     * manager's static map, so the file stays open for the rest of the process.
     */
    static void release(Object connection, String database) {
        closeQuietly(connection);
        if (BSimService.remote()) {
            return;
        }
        try {
            ClassLoader loader = loader();
            Class<?> managerClass = Class.forName(
                "ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager",
                true, loader);
            Class<?> serverInfoClass = Class.forName(SERVER_INFO, true, loader);
            Object serverInfo = serverInfoClass.getConstructor(String.class)
                .newInstance(BSimService.localDatabase(database));
            Object source = managerClass
                .getMethod("getDataSourceIfExists", serverInfoClass)
                .invoke(null, serverInfo);
            if (source == null) {
                return;
            }
            Object active = source.getClass().getMethod("getActiveConnections")
                .invoke(source);
            if (active instanceof Number && ((Number) active).intValue() == 0) {
                source.getClass().getMethod("dispose").invoke(source);
            }
        } catch (Throwable ignored) {
            // No shared source of ours to dispose (another instance may hold it).
        }
    }

    static String lastError(Object connection) {
        try {
            Object error = connection.getClass().getMethod("getLastError")
                .invoke(connection);
            return error == null ? "no reason was reported" : String.valueOf(error);
        } catch (Throwable ignored) {
            return "no reason was reported";
        }
    }

    static void closeQuietly(Object connection) {
        if (connection == null) {
            return;
        }
        try {
            connection.getClass().getMethod("close").invoke(connection);
        } catch (Throwable ignored) {
            // A connection that never came up has nothing to close.
        }
    }

    static void disposeQuietly(Object generator) {
        if (generator == null) {
            return;
        }
        try {
            generator.getClass().getMethod("dispose").invoke(generator);
        } catch (Throwable ignored) {
            // The work already happened or already failed; nothing to report.
        }
    }

    static Map<String, Object> failure(Map<String, Object> data, String code,
            String reason) {
        data.put("success", Boolean.FALSE);
        data.put("code", code);
        data.put("reason", reason);
        return data;
    }

    static Throwable unwrap(Throwable failed) {
        Throwable current = failed;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }

    static String describe(Throwable cause) {
        // Native exceptions can include endpoints, identities and JDBC passwords.
        return "the native BSim operation failed";
    }

    /**
     * A numeric property, whether the API exposes it as a field or as a method.
     *
     * <p>Named `intValue` rather than `intField` on purpose: the old name invited
     * exactly the bug that broke every ingest, where `numFunctions` was read as a
     * field and is a method.
     */
    static int intValue(Object bean, String name) {
        return eu.starsong.ghidra.util.ReflectiveRead.integer(bean, name, 0);
    }

    static boolean booleanField(Object bean, String name) {
        try {
            Object value = bean.getClass().getField(name).get(bean);
            return Boolean.TRUE.equals(value);
        } catch (Throwable missing) {
            return false;
        }
    }

    static String stringField(Object bean, String name) {
        try {
            Object value = bean.getClass().getField(name).get(bean);
            return value == null ? null : String.valueOf(value);
        } catch (Throwable missing) {
            return null;
        }
    }

    static Object call(Object bean, String name, Object... arguments) {
        try {
            for (Method method : bean.getClass().getMethods()) {
                if (!method.getName().equals(name)
                        || method.getParameterCount() != arguments.length) {
                    continue;
                }
                return method.invoke(bean, arguments);
            }
        } catch (Throwable ignored) {
            // The caller treats a null as "not available".
        }
        return null;
    }

    static double secondsSince(long started) {
        return Math.round((System.currentTimeMillis() - started) / 100.0) / 10.0;
    }
}