package eu.starsong.ghidra.service;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Generating BSim signatures for a program and inserting them into a database.
 *
 * <p><b>Everything BSim is reflective on purpose.</b> The API of
 * {@code ghidra.features.bsim.query} is internal and has moved between Ghidra
 * series (this path needs {@code H2FileFunctionDatabase},
 * {@code CreateDatabase}, {@code GenSignatures} and {@code InsertRequest}, none
 * of which is a stable plugin API). The extension is built against the 11.x
 * <em>and</em> 12.x matrix, so a compile-time reference to any of them would
 * break one leg. The discovery half already proved the pattern: ask the class
 * loader, never the version.
 *
 * <p><b>The sequence is Ghidra's own.</b> Copied from
 * {@code AddProgramToH2BSimDatabaseScript} and confirmed against a live run:
 * {@code initialize()} → {@code getInfo()}/{@code getLSHVectorFactory()} →
 * {@code new GenSignatures(trackcallgraph)} → {@code setVectorFactory} →
 * the categories, tags and date column from the database → {@code openProgram}
 * with the real repository and path → {@code scanFunctions} →
 * {@code InsertRequest.execute}. Two measurements shaped this:
 * the {@code GenSignatures} boolean is <em>trackcallgraph</em> (not a cache
 * flag), and a signature generator without a vector factory dies with
 * {@code NullPointerException: LSHVectorFactory.getSettings()} on a database
 * created in the same call.
 *
 * <p><b>A database that does not exist is created, not refused.</b> Measured:
 * {@code initialize()} on a missing H2 file answers
 * {@code "Database does not exist: …mv.db"}. Ghidra's
 * {@code CreateH2BSimDatabaseScript} creates it with a {@code CreateDatabase}
 * command carrying a template ({@code medium_nosize}), which is what happens
 * here when the file is absent.
 *
 * <p>The rules the answer keeps:
 * <ul>
 *   <li>a missing feature or a missing database is a <em>reason</em>, never an
 *       exception that loses the report;</li>
 *   <li>the counts come from BSim's own {@code ResponseInsert}, not from what we
 *       hoped it did;</li>
 *   <li>the database is closed and the signature generator disposed on every
 *       path, because a leaked H2 handle keeps the file locked on Windows.</li>
 * </ul>
 */
public final class BSimIngestService {

    private static final String SERVER_INFO = "ghidra.features.bsim.query.BSimServerInfo";
    private static final String H2_DATABASE = "ghidra.features.bsim.query.file.H2FileFunctionDatabase";
    private static final String GEN_SIGNATURES = "ghidra.features.bsim.query.GenSignatures";
    private static final String INSERT_REQUEST = "ghidra.features.bsim.query.protocol.InsertRequest";
    private static final String CREATE_DATABASE = "ghidra.features.bsim.query.protocol.CreateDatabase";
    private static final String DATABASE_INFO = "ghidra.features.bsim.query.description.DatabaseInformation";
    private static final String BSIM_QUERY = "ghidra.features.bsim.query.protocol.BSimQuery";
    private static final String FUNCTION_DATABASE = "ghidra.features.bsim.query.FunctionDatabase";
    private static final String GHIDRA_URL = "ghidra.framework.protocol.ghidra.GhidraURL";

    /** The template Ghidra's own script uses for a general-purpose database. */
    private static final String DEFAULT_TEMPLATE = "medium_nosize";

    /** A program bigger than this is not a signature job, it is a mistake. */
    public static final int MAX_FUNCTIONS_LIMIT = 200_000;

    private BSimIngestService() {
    }

    /**
     * Generate signatures for {@code program} and insert them into the database
     * named by {@link BSimService#database()}, creating it when it is absent.
     *
     * @param program      the analysed program (never null)
     * @param maxFunctions how many functions to scan at most, 0 for all
     * @return a payload that is always usable: {@code success} says whether the
     *         insert happened, and {@code code}/{@code reason} say why not
     */
    public static Map<String, Object> ingest(Program program, int maxFunctions) {
        return ingest(program, maxFunctions, false);
    }

    /**
     * The same, with the call-graph choice explicit.
     *
     * <p>Measured on Ghidra 12.2 / H2: creating the database with
     * {@code trackcallgraph=true} makes the insert fail with a duplicate
     * {@code callgraphtable(src,dest)} key for a program with normal
     * recursion. The signature tables are exactly what a similarity query
     * needs, so the default is off, and turning it on is a request the caller
     * makes with its eyes open.
     *
     * @param program      the analysed program
     * @param maxFunctions how many functions to scan at most, 0 for all
     * @param trackCallGraph whether the database records the call graph
     * @return the report
     */
    public static Map<String, Object> ingest(Program program, int maxFunctions,
            boolean trackCallGraph) {
        Map<String, Object> data = new LinkedHashMap<>();
        long started = System.currentTimeMillis();
        String database = BSimService.database();

        if (!BSimService.available()) {
            return failure(data, "BSIM_DISABLED",
                "this Ghidra build has no BSim query engine (" + SERVER_INFO
                    + " is not on the classpath)");
        }
        if (database == null) {
            return failure(data, "BSIM_NO_DATABASE",
                "no signature database is configured; set -D"
                    + BSimService.PROPERTY_DATABASE + "=<path> or "
                    + BSimService.ENV_DATABASE + "=<path>");
        }
        if (program == null) {
            return failure(data, "BSIM_NO_PROGRAM", "no program is open in this instance");
        }

        int limit = maxFunctions <= 0 ? Integer.MAX_VALUE
            : Math.min(maxFunctions, MAX_FUNCTIONS_LIMIT);
        data.put("database", database);
        data.put("program", program.getName());
        data.put("track_call_graph", Boolean.valueOf(trackCallGraph));

        List<Function> selected = new ArrayList<>();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        int discovered = 0;
        while (functions.hasNext()) {
            Function function = functions.next();
            discovered++;
            if (selected.size() < limit) {
                selected.add(function);
            }
        }
        data.put("discovered_functions", discovered);
        data.put("scanned_functions", selected.size());
        data.put("skipped_functions", Math.max(0, discovered - selected.size()));

        Object signatureGenerator = null;
        Object connection = null;
        ClassLoader loader = BSimIngestService.class.getClassLoader();
        try {
            Class<?> serverInfoClass = Class.forName(SERVER_INFO, true, loader);
            Object serverInfo = serverInfoClass.getConstructor(String.class)
                .newInstance(database);

            connection = openOrCreate(loader, serverInfoClass, serverInfo, database,
                data, trackCallGraph);
            if (connection == null) {
                data.put("seconds", secondsSince(started));
                return data;
            }

            // ---- what the database says about itself -----------------------
            Class<?> databaseClass = Class.forName(FUNCTION_DATABASE, true, loader);
            Object databaseInfo = connection.getClass().getMethod("getInfo")
                .invoke(connection);
            if (databaseInfo == null) {
                return failure(data, "BSIM_INIT_FAILED",
                    "the signature database answered without its configuration");
            }
            boolean databaseTracksCallGraph =
                booleanField(databaseInfo, "trackcallgraph");
            Object vectorFactory = connection.getClass().getMethod("getLSHVectorFactory")
                .invoke(connection);
            if (vectorFactory == null) {
                return failure(data, "BSIM_INIT_FAILED",
                    "the signature database has no vector factory; it was not "
                        + "created by BSim");
            }

            // ---- signatures ------------------------------------------------
            Class<?> generatorClass = Class.forName(GEN_SIGNATURES, true, loader);
            // The boolean is trackcallgraph: the generator records the call
            // graph only when the database does.
            signatureGenerator = generatorClass.getConstructor(boolean.class)
                .newInstance(Boolean.valueOf(databaseTracksCallGraph));
            generatorClass.getMethod("setVectorFactory",
                    Class.forName("generic.lsh.vector.LSHVectorFactory", true, loader))
                .invoke(signatureGenerator, vectorFactory);
            addList(generatorClass, signatureGenerator, "addExecutableCategories",
                databaseInfo, "execats");
            addList(generatorClass, signatureGenerator, "addFunctionTags",
                databaseInfo, "functionTags");
            String dateColumn = stringField(databaseInfo, "dateColumnName");
            if (dateColumn != null && !dateColumn.isBlank()) {
                generatorClass.getMethod("addDateColumnName", String.class)
                    .invoke(signatureGenerator, dateColumn);
            }

            String[] location = projectLocation(program);
            data.put("repository", location[0]);
            data.put("path", location[1]);
            generatorClass.getMethod("openProgram", Program.class, String.class,
                    String.class, String.class, String.class, String.class)
                .invoke(signatureGenerator, program, null, null, null,
                    location[0], location[1]);

            Method scanFunctions = generatorClass.getMethod("scanFunctions",
                Iterator.class, int.class, TaskMonitor.class);
            scanFunctions.invoke(signatureGenerator, selected.iterator(),
                Integer.valueOf(selected.size()), TaskMonitor.DUMMY);

            Object description = generatorClass.getMethod("getDescriptionManager")
                .invoke(signatureGenerator);
            if (description == null || intMethod(description, "numFunctions") == 0) {
                return failure(data, "BSIM_SCAN_FAILED",
                    "no function with a body could be decompiled, so there was "
                        + "nothing to insert");
            }
            data.put("described_functions", intMethod(description, "numFunctions"));

            // ---- insert ----------------------------------------------------
            Class<?> requestClass = Class.forName(INSERT_REQUEST, true, loader);
            Object request = requestClass.getConstructor().newInstance();
            requestClass.getField("manage").set(request, description);
            Object response = requestClass.getMethod("execute", databaseClass)
                .invoke(request, connection);
            if (response == null) {
                String reason = lastError(connection);
                if (reason != null && reason.toLowerCase().contains("already ingested")) {
                    // BSim deduplicates by executable fingerprint: the program is
                    // in the database, which is exactly what an ingest promises.
                    // Reporting this as a failure would make a pipeline treat a
                    // satisfied goal as broken.
                    data.put("success", Boolean.TRUE);
                    data.put("already_present", Boolean.TRUE);
                    data.put("inserted_functions", 0);
                    data.put("inserted_executables", 0);
                    data.put("reason", reason);
                    data.put("seconds", secondsSince(started));
                    return data;
                }
                return failure(data, "BSIM_INSERT_FAILED",
                    "the database refused the insert: " + reason);
            }

            data.put("success", Boolean.TRUE);
            data.put("inserted_functions", intField(response, "numfunc"));
            data.put("inserted_executables", intField(response, "numexe"));
            data.put("seconds", secondsSince(started));
            return data;
        } catch (Throwable failed) {
            Throwable cause = unwrap(failed);
            data.put("success", Boolean.FALSE);
            data.put("code", "BSIM_INGEST_FAILED");
            data.put("reason", describe(cause));
            data.put("seconds", secondsSince(started));
            return data;
        } finally {
            disposeQuietly(signatureGenerator);
            closeQuietly(connection);
        }
    }

    /**
     * Open the database, creating it first when the H2 file is absent.
     *
     * @return the connected database, or null after putting the failure into
     *         {@code data}
     */
    private static Object openOrCreate(ClassLoader loader, Class<?> serverInfoClass,
            Object serverInfo, String database, Map<String, Object> data,
            boolean trackCallGraph) throws Exception {
        Class<?> h2Class = Class.forName(H2_DATABASE, true, loader);
        Object connection = h2Class.getConstructor(serverInfoClass)
            .newInstance(serverInfo);
        Method initialize = connection.getClass().getMethod("initialize");

        boolean existed = h2FileExists(database);
        if (!existed) {
            String created = create(loader, connection, database, trackCallGraph);
            if (created != null) {
                failure(data, "BSIM_CREATE_FAILED", created);
                return null;
            }
            data.put("created", Boolean.TRUE);
        } else {
            data.put("created", Boolean.FALSE);
        }
        if (!Boolean.TRUE.equals(initialize.invoke(connection))) {
            failure(data, "BSIM_INIT_FAILED",
                "the signature database could not be opened: " + lastError(connection));
            return null;
        }
        return connection;
    }

    /**
     * Create the database with Ghidra's own {@code CreateDatabase} command.
     *
     * @return null on success, or the reason it failed
     */
    private static String create(ClassLoader loader, Object connection, String database,
            boolean trackCallGraph) {
        try {
            Class<?> infoClass = Class.forName(DATABASE_INFO, true, loader);
            Object info = infoClass.getConstructor().newInstance();
            String name = Paths.get(database).getFileName().toString();
            infoClass.getField("databasename").set(info, name);
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
    private static String[] projectLocation(Program program) {
        String[] location = new String[] { null, null };
        try {
            Object domainFile = program.getClass().getMethod("getDomainFile")
                .invoke(program);
            URL fileUrl = null;
            for (String method : new String[] { "getSharedProjectURL", "getLocalProjectURL" }) {
                try {
                    fileUrl = (URL) domainFile.getClass()
                        .getMethod(method, Class.forName("ghidra.framework.model.ProjectLocator"))
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

    private static void addList(Class<?> generatorClass, Object generator,
            String method, Object info, String field) {
        try {
            Object value = info.getClass().getField(field).get(info);
            if (value instanceof List && !((List<?>) value).isEmpty()) {
                generatorClass.getMethod(method, List.class).invoke(generator, value);
            }
        } catch (Throwable ignored) {
            // The database does not carry this list; nothing to add.
        }
    }

    /** Is the H2 file (or any of its companions) on disk? */
    private static boolean h2FileExists(String database) {
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

    private static Map<String, Object> failure(Map<String, Object> data, String code,
            String reason) {
        data.put("success", Boolean.FALSE);
        data.put("code", code);
        data.put("reason", reason);
        return data;
    }

    private static Throwable unwrap(Throwable failed) {
        Throwable current = failed;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }

    private static String describe(Throwable cause) {
        String message = cause.getMessage();
        String type = cause.getClass().getSimpleName();
        return message == null || message.isBlank() ? type : type + ": " + message;
    }

    private static String lastError(Object connection) {
        try {
            Object error = connection.getClass().getMethod("getLastError")
                .invoke(connection);
            return error == null ? "no reason was reported" : String.valueOf(error);
        } catch (Throwable ignored) {
            return "no reason was reported";
        }
    }

    private static int intField(Object bean, String name) {
        try {
            Field field = bean.getClass().getField(name);
            Object value = field.get(bean);
            return value instanceof Number ? ((Number) value).intValue() : 0;
        } catch (Throwable missing) {
            return 0;
        }
    }

    private static boolean booleanField(Object bean, String name) {
        try {
            Object value = bean.getClass().getField(name).get(bean);
            return Boolean.TRUE.equals(value);
        } catch (Throwable missing) {
            return false;
        }
    }

    private static String stringField(Object bean, String name) {
        try {
            Object value = bean.getClass().getField(name).get(bean);
            return value == null ? null : String.valueOf(value);
        } catch (Throwable missing) {
            return null;
        }
    }

    private static int intMethod(Object bean, String name) {
        try {
            Object value = bean.getClass().getMethod(name).invoke(bean);
            return value instanceof Number ? ((Number) value).intValue() : 0;
        } catch (Throwable missing) {
            return 0;
        }
    }

    private static double secondsSince(long started) {
        return Math.round((System.currentTimeMillis() - started) / 100.0) / 10.0;
    }

    private static void disposeQuietly(Object generator) {
        if (generator == null) {
            return;
        }
        try {
            generator.getClass().getMethod("dispose").invoke(generator);
        } catch (Throwable ignored) {
            // The insert already happened or already failed; nothing to report.
        }
    }

    private static void closeQuietly(Object connection) {
        if (connection == null) {
            return;
        }
        try {
            connection.getClass().getMethod("close").invoke(connection);
        } catch (Throwable ignored) {
            // A connection that never came up has nothing to close.
        }
    }
}