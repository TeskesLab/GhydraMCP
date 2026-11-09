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
 *   <li>the database is closed and the signature generator disposed on every
 *       path, because a leaked H2 handle keeps the file locked on Windows.</li>
 * </ul>
 */
public final class BSimIngestService {

    /** A program bigger than this is not a signature job, it is a mistake. */
    public static final int MAX_FUNCTIONS_LIMIT = 200_000;

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

        int limit = maxFunctions <= 0 ? Integer.MAX_VALUE
            : Math.min(maxFunctions, MAX_FUNCTIONS_LIMIT);
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
            Object describedCount = description == null ? null
                : BSimDatabase.call(description, "numFunctions");
            int described = describedCount instanceof Number
                ? ((Number) describedCount).intValue() : 0;
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
                    // BSim deduplicates by executable fingerprint: the program is
                    // in the database, which is exactly what an ingest promises.
                    // Reporting this as a failure would make a pipeline treat a
                    // satisfied goal as broken.
                    data.put("success", Boolean.TRUE);
                    data.put("already_present", Boolean.TRUE);
                    data.put("inserted_functions", 0);
                    data.put("inserted_executables", 0);
                    data.put("reason", reason);
                    data.put("seconds", BSimDatabase.secondsSince(started));
                    return data;
                }
                return BSimDatabase.failure(data, "BSIM_INSERT_FAILED",
                    "the database refused the insert: " + reason);
            }

            data.put("success", Boolean.TRUE);
            data.put("inserted_functions", BSimDatabase.intField(response, "numfunc"));
            data.put("inserted_executables", BSimDatabase.intField(response, "numexe"));
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
}
