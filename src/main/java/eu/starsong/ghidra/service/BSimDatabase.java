package eu.starsong.ghidra.service;

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
        try {
            ClassLoader loader = loader();
            Class<?> serverInfoClass = Class.forName(SERVER_INFO, true, loader);
            Object serverInfo = serverInfoClass.getConstructor(String.class)
                .newInstance(database);
            Class<?> h2Class = Class.forName(H2_DATABASE, true, loader);
            Object connection = h2Class.getConstructor(serverInfoClass)
                .newInstance(serverInfo);

            boolean existed = exists(database);
            if (!existed) {
                if (!createWhenMissing) {
                    failure(data, "BSIM_NO_DATABASE",
                        "the signature database does not exist: " + database
                            + " (ingest a program first)");
                    return null;
                }
                String created = create(connection, database);
                if (created != null) {
                    failure(data, "BSIM_CREATE_FAILED", created);
                    return null;
                }
                data.put("created", Boolean.TRUE);
            } else {
                data.put("created", Boolean.FALSE);
            }
            if (!Boolean.TRUE.equals(
                    connection.getClass().getMethod("initialize").invoke(connection))) {
                failure(data, "BSIM_INIT_FAILED",
                    "the signature database could not be opened: " + lastError(connection));
                return null;
            }
            return connection;
        } catch (Throwable failed) {
            failure(data, "BSIM_INIT_FAILED", describe(unwrap(failed)));
            return null;
        }
    }

    /** Create the database with Ghidra's own {@code CreateDatabase} command. */
    private static String create(Object connection, String database) {
        try {
            ClassLoader loader = loader();
            Class<?> infoClass = Class.forName(DATABASE_INFO, true, loader);
            Object info = infoClass.getConstructor().newInstance();
            infoClass.getField("databasename")
                .set(info, Paths.get(database).getFileName().toString());
            infoClass.getField("trackcallgraph").set(info, Boolean.FALSE);

            Class<?> commandClass = Class.forName(CREATE_DATABASE, true, loader);
            Object command = commandClass.getConstructor().newInstance();
            commandClass.getField("info").set(command, info);
            commandClass.getField("config_template").set(command, DEFAULT_TEMPLATE);
            Class<?> databaseClass = Class.forName(FUNCTION_DATABASE, true, loader);
            Object response = commandClass.getMethod("execute", databaseClass)
                .invoke(command, connection);
            if (response == null) {
                return "the database was created but answered with no response: "
                    + lastError(connection);
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
    static String[] projectLocation(Program program) {
        String[] location = new String[] { null, null };
        try {
            Object domainFile = program.getClass().getMethod("getDomainFile")
                .invoke(program);
            URL fileUrl = null;
            for (String method : new String[] { "getSharedProjectURL",
                    "getLocalProjectURL" }) {
                try {
                    fileUrl = (URL) domainFile.getClass()
                        .getMethod(method,
                            Class.forName("ghidra.framework.model.ProjectLocator"))
                        .invoke(domainFile, new Object[] { null });
                } catch (Throwable ignored) {
                    // Try the next accessor.
                }
                if (fileUrl != null) {
                    break;
                }
            }
            if (fileUrl == null) {
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
        String message = cause.getMessage();
        String type = cause.getClass().getSimpleName();
        return message == null || message.isBlank() ? type : type + ": " + message;
    }

    static int intField(Object bean, String name) {
        try {
            Field field = bean.getClass().getField(name);
            Object value = field.get(bean);
            return value instanceof Number ? ((Number) value).intValue() : 0;
        } catch (Throwable missing) {
            return 0;
        }
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