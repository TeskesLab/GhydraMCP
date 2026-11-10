package eu.starsong.ghidra.service;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Generating BSim signatures for a program and inserting them into a database.
 *
 * <p><b>Everything BSim is reflective on purpose</b> (see {@link BSimDatabase}):
 * the API is internal and has moved between series, and the extension builds
 * against 11.x and 12.x.
 *
 * <p><b>The sequence is Ghidra's own</b>, copied from
 * {@code AddProgramToH2BSimDatabaseScript} and corrected against a live run:
 * {@code initialize()} → {@code getInfo()}/{@code getLSHVectorFactory()} →
 * {@code new GenSignatures(trackcallgraph)} → {@code setVectorFactory} → the
 * categories, tags and date column from the database → {@code openProgram} with
 * the real repository and path → {@code scanFunctions} →
 * {@code InsertRequest.execute}. Two measurements shaped this: the
 * {@code GenSignatures} boolean is <em>trackcallgraph</em> (not a cache flag),
 * and a generator without a vector factory dies with
 * {@code NullPointerException: LSHVectorFactory.getSettings()} on a database
 * created in the same call.
 *
 * <p><b>A database that does not exist is created.</b> Measured:
 * {@code initialize()} on a missing H2 file answers
 * {@code "Database does not exist: …mv.db"}, so the create happens first, with
 * Ghidra's {@code CreateDatabase} command and the {@code medium_nosize} template.
 *
 * <p>The rules the answer keeps:
 * <ul>
 *   <li>a missing feature or a missing database is a <em>reason</em>, never an
 *       exception that loses the report;</li>
 *   <li>the counts come from BSim's own {@code ResponseInsert}, not from what we
 *       hoped it did;</li>
 *   <li>a refusal is not a success: "already ingested" is a success only when
 *       the stored ingest covers every function of the program, because BSim
 *       refuses a second insert of the same binary <em>before</em> it inserts
 *       any function — a capped ingest stays a partial corpus, and a later,
 *       larger ingest cannot complete it;</li>
 *   <li>the database is closed and the signature generator disposed on every
 *       path, because a leaked H2 handle keeps the file locked on Windows.</li>
 * </ul>
 */
public final class BSimIngestService {

    /** A program bigger than this is not a signature job, it is a mistake. */
    public static final int MAX_FUNCTIONS_LIMIT = 200_000;

    /**
     * What an ingest without a limit does: 5 000 functions.
     *
     * <p>The work is a decompilation per function, so "all of them" on a large
     * binary is hours inside one request — the client gives up at its timeout, the
     * Jetty thread stays busy, and the answer is lost. The caller who wants
     * everything asks for it with {@code max_functions=0}.
     */
    public static final int DEFAULT_MAX_FUNCTIONS = 5_000;

    /**
     * The number of functions an ingest of {@code requested} will scan.
     *
     * <p>Negative (absent) is the default, {@code 0} is everything, and anything
     * above {@link #MAX_FUNCTIONS_LIMIT} is clamped to it. Static and pure: it is
     * what {@code BSimIngestServiceTest} pins.
     */
    static int capFor(int requested) {
        if (requested < 0) {
            return DEFAULT_MAX_FUNCTIONS;
        }
        if (requested == 0) {
            return Integer.MAX_VALUE;
        }
        return Math.min(requested, MAX_FUNCTIONS_LIMIT);
    }

    private BSimIngestService() {
    }

    /** Ingest with the call graph off: the default and the measured-safe choice. */
    public static Map<String, Object> ingest(Program program, int maxFunctions) {
        return ingest(program, maxFunctions, false);
    }

    /**
     * Generate signatures for {@code program} and insert them into the database
     * named by {@link BSimService#database()}, creating it when it is absent.
     *
     * <p>Measured on Ghidra 12.2 / H2: creating the database with
     * {@code trackcallgraph=true} makes the insert fail with a duplicate
     * {@code callgraphtable(src,dest)} key for a program with normal recursion.
     * The signature tables are exactly what a similarity query needs, so the
     * default is off and turning it on is a request the caller makes knowingly.
     *
     * @param program       the analysed program (never null)
     * @param maxFunctions  how many functions to scan at most, 0 for all
     * @param trackCallGraph whether the database records the call graph
     * @return a payload that is always usable: {@code success} says whether the
     *         insert happened, and {@code code}/{@code reason} say why not
     */
    public static Map<String, Object> ingest(Program program, int maxFunctions,
            boolean trackCallGraph) {
        Map<String, Object> data = new LinkedHashMap<>();
        long started = System.currentTimeMillis();
        String database = BSimService.database();

        if (!BSimService.available()) {
            return BSimDatabase.failure(data, "BSIM_DISABLED",
                "this Ghidra build has no BSim query engine ("
                    + BSimDatabase.SERVER_INFO + " is not on the classpath)");
        }
        if (database == null) {
            return BSimDatabase.failure(data, "BSIM_NO_DATABASE",
                "no signature database is configured; set -D"
                    + BSimService.PROPERTY_DATABASE + "=<path> or "
                    + BSimService.ENV_DATABASE + "=<path>");
        }
        if (program == null) {
            return BSimDatabase.failure(data, "BSIM_NO_PROGRAM",
                "no program is open in this instance");
        }

        int limit = capFor(maxFunctions);
        data.put("database", database);
        data.put("program", program.getName());
        data.put("track_call_graph", Boolean.valueOf(trackCallGraph));

        // Selecting functions traverses the program database, so it happens under
        // the EDT (the repo's rule) and only the references are kept. The
        // decompilation and the BSim work stay outside, or they would freeze an
        // open CodeBrowser for the whole scan.
        final int wanted = limit;
        int[] discoveredHolder = new int[1];
        List<Function> selected = GhidraSwing.runRead(() -> {
            List<Function> chosen = new ArrayList<>();
            FunctionIterator functions =
                program.getFunctionManager().getFunctions(true);
            int seen = 0;
            while (functions.hasNext()) {
                Function function = functions.next();
                seen++;
                if (chosen.size() < wanted) {
                    chosen.add(function);
                }
            }
            discoveredHolder[0] = seen;
            return chosen;
        });
        int discovered = discoveredHolder[0];
        data.put("discovered_functions", discovered);
        data.put("functions_cap", limit == Integer.MAX_VALUE ? null
            : Integer.valueOf(limit));
        // A scan that stopped at the cap is not the whole program: say so, or a
        // later query will read "not in the corpus" from a partial ingest.
        // The flag is corrected below when the database refuses an insert
        // because the executable is already there: then the cap of what is
        // STORED is what counts, not the cap of this scan.
        data.put("capped", Boolean.valueOf(discovered > limit));
        data.put("scanned_functions", selected.size());
        data.put("skipped_functions", Math.max(0, discovered - selected.size()));

        Object signatureGenerator = null;
        Object connection = null;
        try {
            connection = BSimDatabase.open(database, true, trackCallGraph, data);
            if (connection == null) {
                return data;
            }

            ClassLoader loader = BSimDatabase.loader();
            Class<?> databaseClass = Class.forName(BSimDatabase.FUNCTION_DATABASE,
                true, loader);
            Object databaseInfo = connection.getClass().getMethod("getInfo")
                .invoke(connection);
            if (databaseInfo == null) {
                return BSimDatabase.failure(data, "BSIM_INIT_FAILED",
                    "the signature database answered without its configuration");
            }
            Object vectorFactory = connection.getClass()
                .getMethod("getLSHVectorFactory").invoke(connection);
            if (vectorFactory == null) {
                return BSimDatabase.failure(data, "BSIM_INIT_FAILED",
                    "the signature database has no vector factory; it was not "
                        + "created by BSim");
            }

            Class<?> generatorClass = Class.forName(BSimDatabase.GEN_SIGNATURES,
                true, loader);
            signatureGenerator = generatorClass.getConstructor(boolean.class)
                .newInstance(Boolean.valueOf(
                    BSimDatabase.booleanField(databaseInfo, "trackcallgraph")));
            generatorClass.getMethod("setVectorFactory",
                    Class.forName("generic.lsh.vector.LSHVectorFactory", true, loader))
                .invoke(signatureGenerator, vectorFactory);
            BSimDatabase.addList(signatureGenerator, databaseInfo,
                "addExecutableCategories", "execats");
            BSimDatabase.addList(signatureGenerator, databaseInfo, "addFunctionTags",
                "functionTags");
            String dateColumn = BSimDatabase.stringField(databaseInfo, "dateColumnName");
            if (dateColumn != null && !dateColumn.isBlank()) {
                generatorClass.getMethod("addDateColumnName", String.class)
                    .invoke(signatureGenerator, dateColumn);
            }

            String[] location = BSimDatabase.projectLocation(program);
            data.put("repository", location[0]);
            data.put("path", location[1]);
            data.put("location_reason", location[2]);
            generatorClass.getMethod("openProgram", Program.class, String.class,
                    String.class, String.class, String.class, String.class)
                .invoke(signatureGenerator, program, null, null, null,
                    location[0], location[1]);

            generatorClass.getMethod("scanFunctions", Iterator.class, int.class,
                    TaskMonitor.class)
                .invoke(signatureGenerator, selected.iterator(),
                    Integer.valueOf(selected.size()), TaskMonitor.DUMMY);

            Object description = generatorClass.getMethod("getDescriptionManager")
                .invoke(signatureGenerator);
            // `numFunctions` is a METHOD on DescriptionManager (measured with
            // javap against Ghidra 12.2, and how the official script calls it).
            // Reading it as a field returned 0 and made every ingest fail with
            // BSIM_SCAN_FAILED.
            int described = BSimDatabase.intValue(description, "numFunctions");
            if (described == 0) {
                return BSimDatabase.failure(data, "BSIM_SCAN_FAILED",
                    "no function with a body could be decompiled, so there was "
                        + "nothing to insert");
            }
            data.put("described_functions", described);

            // The official script sorts every call-graph record before the
            // insert (`listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph())`),
            // and without it a database with the call graph on rejects the insert
            // with a duplicate callgraphtable(src,dest) key. That is the real
            // cause of the duplicate-key failure seen earlier — not "call graphs
            // are broken on H2".
            sortCallgraph(description);

            Class<?> requestClass = Class.forName(
                "ghidra.features.bsim.query.protocol.InsertRequest", true, loader);
            Object request = requestClass.getConstructor().newInstance();
            requestClass.getField("manage").set(request, description);
            Object response = requestClass.getMethod("execute", databaseClass)
                .invoke(request, connection);
            if (response == null) {
                String reason = BSimDatabase.lastError(connection);
                if (reason != null && reason.toLowerCase().contains("already ingested")) {
                    // BSim keys an executable by its fingerprint and refuses a
                    // second insert of the same binary BEFORE it inserts a
                    // single function, so the functions of a previously capped
                    // ingest are never completed by a later, larger one. The
                    // refusal is therefore not the promise it looks like: what
                    // the database holds has to be counted before it can be
                    // called a success.
                    return reportAlreadyIngested(data, program, connection,
                        description, selected.size(), discovered, described,
                        reason, started);
                }
                return BSimDatabase.failure(data, "BSIM_INSERT_FAILED",
                    "the database refused the insert: " + reason);
            }

            data.put("success", Boolean.TRUE);
            data.put("inserted_functions", BSimDatabase.intValue(response, "numfunc"));
            data.put("inserted_executables", BSimDatabase.intValue(response, "numexe"));
            data.put("seconds", BSimDatabase.secondsSince(started));
            return data;
        } catch (Throwable failed) {
            Throwable cause = BSimDatabase.unwrap(failed);
            data.put("success", Boolean.FALSE);
            data.put("code", "BSIM_INGEST_FAILED");
            data.put("reason", BSimDatabase.describe(cause));
            data.put("seconds", BSimDatabase.secondsSince(started));
            return data;
        } finally {
            BSimDatabase.disposeQuietly(signatureGenerator);
            BSimDatabase.closeQuietly(connection);
        }
    }

    /**
     * Sort each function's call-graph records, the way Ghidra's own script does.
     *
     * <p>The official {@code AddProgramToH2BSimDatabaseScript} calls
     * {@code listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph())} before
     * the insert, and without it a database with the call graph on rejects the
     * insert with a duplicate {@code callgraphtable(src,dest)} key. That is the
     * real cause of the duplicate-key failure seen earlier — not "call graphs are
     * broken on H2". Reflective like the rest of the BSim API; a failure here is
     * not fatal.
     */
    private static void sortCallgraph(Object description) {
        try {
            Object functions = BSimDatabase.call(description, "listAllFunctions");
            java.util.Iterator<?> iterator = null;
            if (functions instanceof Iterable) {
                iterator = ((Iterable<?>) functions).iterator();
            } else if (functions instanceof java.util.Iterator) {
                iterator = (java.util.Iterator<?>) functions;
            }
            while (iterator != null && iterator.hasNext()) {
                BSimDatabase.call(iterator.next(), "sortCallgraph");
            }
        } catch (Throwable ignored) {
            // No call graph to sort: the insert is unaffected.
        }
    }

    /**
     * What the database already holds for this program, and whether that is
     * the whole program.
     *
     * <p>BSim refuses a second insert of the same executable by fingerprint,
     * and it refuses it <em>before</em> it inserts any function. So an
     * executable that was ingested with a cap stays a partial corpus forever,
     * and a later, larger ingest answers "already ingested" while the
     * database still holds the first subset. Answering that with a success
     * claims a complete corpus that does not exist, so the stored set is
     * counted and compared with what this program can produce.
     *
     * @param data        the answer being built
     * @param program     the program that was ingested
     * @param connection  the open database
     * @param description the signatures that were generated for the program
     * @param scanned     how many functions this scan covered
     * @param discovered  how many functions the program has
     * @param described   how many of the scanned functions produced a signature
     * @param reason      the refusal the database gave
     * @param started     when the ingest began, for the timing
     * @return the answer: a success when the stored ingest is complete, an
     *         explicit failure when it is not
     */
    private static Map<String, Object> reportAlreadyIngested(Map<String, Object> data,
            Program program, Object connection, Object description, int scanned,
            int discovered, int described, String reason, long started) {
        String md5 = executableMd5(description, program);
        int stored = storedFunctionCount(connection, md5);
        // A scan that covered the whole program says exactly how many
        // signatures the corpus should hold; a capped scan does not, and the
        // program itself is then the only honest yardstick.
        int expected = scanned >= discovered ? described
            : countFunctionsWithBody(program);
        data.put("stored_executable_md5", md5);
        data.put("stored_functions", stored < 0 ? null : Integer.valueOf(stored));
        data.put("expected_functions", Integer.valueOf(expected));
        if (stored < 0) {
            // The count could not be read: a partial store must never be
            // reported as a success, so this is a failure with the reason.
            data.put("capped", Boolean.TRUE);
            data.put("seconds", BSimDatabase.secondsSince(started));
            return BSimDatabase.failure(data, "BSIM_INCOMPLETE_INGEST",
                "the database already holds this executable, but the stored "
                    + "ingest could not be counted, so it cannot be shown to "
                    + "cover every function of the program. " + reason);
        }
        if (storedIngestIsComplete(stored, expected)) {
            data.put("success", Boolean.TRUE);
            data.put("already_present", Boolean.TRUE);
            data.put("inserted_functions", 0);
            data.put("inserted_executables", 0);
            data.put("capped", Boolean.FALSE);
            data.put("reason", reason);
            data.put("seconds", BSimDatabase.secondsSince(started));
            return data;
        }
        data.put("capped", Boolean.TRUE);
        data.put("seconds", BSimDatabase.secondsSince(started));
        return BSimDatabase.failure(data, "BSIM_INCOMPLETE_INGEST",
            "the database holds " + stored + " signatures for this executable, "
                + "which does not cover the " + expected + " functions of the "
                + "program: the stored ingest was capped, and BSim keys "
                + "executables by fingerprint, so a later ingest cannot add "
                + "the missing functions to it. Ingest the program under a "
                + "different executable name, or delete the partial record "
                + "from the database, and ingest again.");
    }

    /**
     * Does the stored ingest cover the whole program?
     *
     * <p>A count that could not be read is never a complete store: the answer
     * has to be provable, not probable.
     *
     * @param stored   how many signatures the database holds for the executable
     * @param expected how many the program can produce
     * @return true when the store covers the program
     */
    static boolean storedIngestIsComplete(int stored, int expected) {
        if (stored < 0 || expected < 0) {
            return false;
        }
        return stored >= expected;
    }

    /**
     * The fingerprint the database keys this program by.
     *
     * <p>The record BSim itself built for the program is asked first, because
     * that is the fingerprint it used: a program with no fingerprint of its
     * own is keyed by one BSim derives from its metadata.
     *
     * @param description the signatures that were generated for the program
     * @param program     the program that was ingested
     * @return the fingerprint, or null when it could not be determined
     */
    private static String executableMd5(Object description, Program program) {
        Object records = BSimDatabase.call(description, "getExecutableRecordSet");
        if (records instanceof Iterable) {
            for (Object record : (Iterable<?>) records) {
                if (Boolean.TRUE.equals(BSimDatabase.call(record, "isLibrary"))) {
                    // A library is inserted in pieces on purpose; it is not the
                    // executable this program was ingested as.
                    continue;
                }
                String md5 = (String) BSimDatabase.call(record, "getMd5");
                if (md5 != null && md5.length() >= 10) {
                    return md5;
                }
            }
        }
        try {
            String md5 = program.getExecutableMD5();
            if (md5 != null && md5.length() >= 10) {
                return md5;
            }
        } catch (Throwable ignored) {
            // The program cannot name its own fingerprint.
        }
        return null;
    }

    /**
     * How many signatures the database holds for an executable.
     *
     * <p>Counted in the database itself: the executable table holds one row
     * per ingested binary and the description table one row per ingested
     * function. Reflective, because the JDBC connection is behind the
     * database's own field.
     *
     * @param connection the open database
     * @param md5        the fingerprint of the executable
     * @return the number of stored functions, or -1 when it cannot be read
     */
    private static int storedFunctionCount(Object connection, String md5) {
        if (connection == null || md5 == null || md5.isBlank()) {
            return -1;
        }
        java.sql.Connection jdbc = null;
        try {
            jdbc = jdbcConnection(connection);
            if (jdbc == null) {
                return -1;
            }
            long executableId;
            try (java.sql.PreparedStatement statement = jdbc.prepareStatement(
                    "SELECT id FROM exetable WHERE md5 = ?")) {
                statement.setString(1, md5);
                try (java.sql.ResultSet rows = statement.executeQuery()) {
                    if (!rows.next()) {
                        return -1;
                    }
                    executableId = rows.getLong(1);
                }
            }
            try (java.sql.PreparedStatement statement = jdbc.prepareStatement(
                    "SELECT COUNT(*) FROM desctable WHERE id_exe = ?")) {
                statement.setLong(1, executableId);
                try (java.sql.ResultSet rows = statement.executeQuery()) {
                    if (!rows.next()) {
                        return -1;
                    }
                    return rows.getInt(1);
                }
            }
        } catch (Throwable unavailable) {
            // The schema is BSim's own; a build that changed it cannot be
            // counted, and an uncounted store is never a complete one.
            return -1;
        } finally {
            if (jdbc != null) {
                try {
                    jdbc.close();
                } catch (Throwable ignored) {
                    // The pool takes the connection back on its own.
                }
            }
        }
    }

    /**
     * The JDBC connection of an open BSim database, or null.
     *
     * <p>The database keeps its data source in a protected field of its own
     * base class, so the field is read reflectively — the same reason every
     * other part of the BSim API is used reflectively.
     */
    private static java.sql.Connection jdbcConnection(Object database) {
        try {
            Class<?> type = database.getClass();
            while (type != null) {
                Field field;
                try {
                    field = type.getDeclaredField("ds");
                } catch (NoSuchFieldException missing) {
                    type = type.getSuperclass();
                    continue;
                }
                field.setAccessible(true);
                Object source = field.get(database);
                if (source == null) {
                    return null;
                }
                Class<?> contract = Class.forName(
                    "ghidra.features.bsim.query.BSimJDBCDataSource", true,
                    BSimDatabase.loader());
                return (java.sql.Connection) contract.getMethod("getConnection")
                    .invoke(source);
            }
        } catch (Throwable unavailable) {
            // No JDBC connection could be reached.
        }
        return null;
    }

    /**
     * How many functions of the program have a body.
     *
     * <p>A function without a body (an external, a thunk) produces no
     * signature, so it is not part of what a complete ingest can hold. The
     * count is the yardstick for a capped scan, which cannot say on its own
     * how many signatures the program yields.
     */
    private static int countFunctionsWithBody(Program program) {
        return GhidraSwing.runRead(() -> {
            int bodies = 0;
            FunctionIterator functions =
                program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                if (function.getBody() != null
                        && function.getBody().getNumAddresses() > 0) {
                    bodies++;
                }
            }
            return bodies;
        });
    }
}
