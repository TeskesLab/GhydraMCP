package eu.starsong.ghidra.service;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

/**
 * Signature similarity: which functions in the database look like this one.
 *
 * <p>This is the other half of R1. Ingest puts a program's signatures into the
 * database; a query asks it, for one function of the open program, which stored
 * functions are similar, with BSim's own similarity and significance numbers.
 *
 * <p><b>Reflective for the same reason as ingest:</b> {@code QueryNearest},
 * {@code GenSignatures}, {@code ResponseNearest} and {@code SimilarityNote} are
 * internal API, and the extension builds against Ghidra 11.x and 12.x.
 *
 * <p>The sequence is Ghidra's own ({@code QueryFunction} /
 * {@code LocalBSimQueryScript}): open the database, build a signature for the
 * single function being asked about, put that description in a
 * {@code QueryNearest}, execute it, and read the notes. The answers keep three
 * rules:
 * <ul>
 *   <li>a match that is only "similar" is reported with the number that says how
 *       similar — never as an identification;</li>
 *   <li>an empty answer says the threshold it used, so the reader can tell "no
 *       such function in the corpus" from "the corpus was not searched well";</li>
 *   <li>a query needs the function to have a body; a thunk or an external has no
 *       signature, and the answer says so instead of returning nothing.</li>
 * </ul>
 */
public final class BSimQueryService {

    /** The default similarity threshold BSim itself uses. */
    public static final double DEFAULT_SIMILARITY = 0.7;

    /** The default significance threshold BSim itself uses. */
    public static final double DEFAULT_SIGNIFICANCE = 0.0;

    /** How many matches to ask BSim for, at most. */
    public static final int DEFAULT_MAX_MATCHES = 10;

    /** A cap the answer must still respect. */
    public static final int MAX_MATCHES_LIMIT = 200;

    private BSimQueryService() {
    }

    /**
     * Query the database for functions similar to one of the open program's.
     *
     * @param program       the open program
     * @param address       the function address, or null when a name is used
     * @param name          the function name, or null when an address is used
     * @param maxMatches    how many matches to return, 0 for the default
     * @param minSimilarity the similarity floor, 0 for the default
     * @param minSignificance the significance floor, 0 for the default
     * @return the report; {@code success} says whether the query ran, and the
     *         matches are in {@code matches}
     */
    public static Map<String, Object> query(Program program, String address,
            String name, int maxMatches, double minSimilarity,
            double minSignificance) {
        Map<String, Object> data = new LinkedHashMap<>();
        long started = System.currentTimeMillis();
        String database = BSimService.database();

        if (!BSimService.available()) {
            return BSimDatabase.failure(data, "BSIM_DISABLED",
                "this Ghidra build has no BSim query engine");
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

        int limit = maxMatches <= 0 ? DEFAULT_MAX_MATCHES
            : Math.min(maxMatches, MAX_MATCHES_LIMIT);
        double similarity = minSimilarity <= 0 ? DEFAULT_SIMILARITY
            : Math.min(minSimilarity, 1.0);
        double significance = minSignificance <= 0 ? DEFAULT_SIGNIFICANCE
            : minSignificance;

        Function function = resolveFunction(program, address, name);
        if (function == null) {
            return BSimDatabase.failure(data, "BSIM_NO_FUNCTION",
                address != null
                    ? "no function at " + address
                    : "no function named " + name + " in this program");
        }
        if (function.getBody() == null || function.getBody().getNumAddresses() == 0) {
            return BSimDatabase.failure(data, "BSIM_NO_BODY",
                "the function has no body, so no signature can be made for it");
        }

        data.put("database", database);
        data.put("program", program.getName());
        data.put("function", function.getName());
        data.put("address", function.getEntryPoint().toString());
        data.put("min_similarity", similarity);
        data.put("min_significance", significance);
        data.put("max_matches", limit);

        Object signatureGenerator = null;
        Object connection = BSimDatabase.open(database, false, data);
        if (connection == null) {
            return data;
        }
        try {
            ClassLoader loader = BSimDatabase.loader();
            Class<?> databaseClass = Class.forName(BSimDatabase.FUNCTION_DATABASE,
                true, loader);
            Object databaseInfo = connection.getClass().getMethod("getInfo")
                .invoke(connection);
            Object vectorFactory = connection.getClass()
                .getMethod("getLSHVectorFactory").invoke(connection);
            if (databaseInfo == null || vectorFactory == null) {
                return BSimDatabase.failure(data, "BSIM_INIT_FAILED",
                    "the signature database answered without its configuration");
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
            generatorClass.getMethod("openProgram", Program.class, String.class,
                    String.class, String.class, String.class, String.class)
                .invoke(signatureGenerator, program, null, null, null,
                    location[0], location[1]);
            // One function: the one being asked about.
            generatorClass.getMethod("scanFunction", Function.class)
                .invoke(signatureGenerator, function);

            Object description = generatorClass.getMethod("getDescriptionManager")
                .invoke(signatureGenerator);
            if (description == null) {
                return BSimDatabase.failure(data, "BSIM_SCAN_FAILED",
                    "no signature could be generated for this function");
            }

            Class<?> queryClass = Class.forName(
                "ghidra.features.bsim.query.protocol.QueryNearest", true, loader);
            Object query = queryClass.getConstructor().newInstance();
            queryClass.getField("manage").set(query, description);
            queryClass.getField("thresh").set(query, Double.valueOf(similarity));
            queryClass.getField("signifthresh").set(query,
                Double.valueOf(significance));
            queryClass.getField("max").set(query, Integer.valueOf(limit));

            Object response = queryClass.getMethod("execute", databaseClass)
                .invoke(query, connection);
            if (response == null) {
                return BSimDatabase.failure(data, "BSIM_QUERY_FAILED",
                    "the database refused the query: "
                        + BSimDatabase.lastError(connection));
            }

            List<Map<String, Object>> matches = new ArrayList<>();
            List<?> results = (List<?>) BSimDatabase.call(response, "getResult");
            if (results == null) {
                results = (List<?>) fieldOf(response, "result");
            }
            int total = 0;
            if (results != null) {
                for (Object result : results) {
                    Iterator<?> notes = iterate(result);
                    while (notes != null && notes.hasNext() && matches.size() < limit) {
                        Object note = notes.next();
                        total++;
                        matches.add(describeNote(note));
                    }
                }
            }

            data.put("success", Boolean.TRUE);
            data.put("matches", matches);
            data.put("returned", matches.size());
            data.put("total_considered", total);
            data.put("method", "BSim similarity over the signature database; a "
                + "match is a lead, not an identification.");
            data.put("seconds", BSimDatabase.secondsSince(started));
            if (matches.isEmpty()) {
                data.put("reason", "no stored function is at least "
                    + similarity + " similar (threshold used)");
            }
            return data;
        } catch (Throwable failed) {
            Throwable cause = BSimDatabase.unwrap(failed);
            data.put("success", Boolean.FALSE);
            data.put("code", "BSIM_QUERY_FAILED");
            data.put("reason", BSimDatabase.describe(cause));
            data.put("seconds", BSimDatabase.secondsSince(started));
            return data;
        } finally {
            BSimDatabase.disposeQuietly(signatureGenerator);
            BSimDatabase.closeQuietly(connection);
        }
    }

    private static Function resolveFunction(Program program, String address,
            String name) {
        try {
            if (address != null && !address.isBlank()) {
                Address target = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(address.trim());
                return program.getFunctionManager().getFunctionAt(target);
            }
            if (name == null || name.isBlank()) {
                return null;
            }
            FunctionIterator functions =
                program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function candidate = functions.next();
                if (name.equals(candidate.getName())) {
                    return candidate;
                }
            }
            // No getFunction(String) in this Ghidra series: the walk above is
            // the lookup, and an unknown name is simply not found.
            return null;
        } catch (RuntimeException invalid) {
            return null;
        } catch (Exception invalid) {
            // AddressFormatException is checked; a bad address is "not found".
            return null;
        }
    }

    private static Object fieldOf(Object bean, String name) {
        try {
            Field field = bean.getClass().getField(name);
            return field.get(bean);
        } catch (Throwable missing) {
            return null;
        }
    }

    private static Iterator<?> iterate(Object collection) {
        if (collection instanceof Iterable) {
            return ((Iterable<?>) collection).iterator();
        }
        return null;
    }

    private static Map<String, Object> describeNote(Object note) {
        Map<String, Object> match = new LinkedHashMap<>();
        Object described = BSimDatabase.call(note, "getFunctionDescription");
        String function = null;
        String address = null;
        String executable = null;
        String path = null;
        if (described != null) {
            function = (String) BSimDatabase.call(described, "getFunctionName");
            Object addressValue = BSimDatabase.call(described, "getAddress");
            address = addressValue == null ? null
                : "0x" + Long.toHexString(((Number) addressValue).longValue());
            Object exe = BSimDatabase.call(described, "getExecutableRecord");
            if (exe != null) {
                // The executable record calls the name `getNameExec`: measured,
                // `getName()` exists but answers null, so the match came back
                // with an empty "executable" and the reader could not tell which
                // binary it was.
                executable = (String) BSimDatabase.call(exe, "getNameExec");
                if (executable == null) {
                    executable = (String) BSimDatabase.call(exe, "getName");
                }
                path = (String) BSimDatabase.call(exe, "getPath");
            }
        }
        match.put("function", function);
        match.put("address", address);
        match.put("executable", executable);
        match.put("path", path);
        match.put("similarity", doubleOf(note, "getSimilarity"));
        match.put("significance", doubleOf(note, "getSignificance"));
        return match;
    }

    private static double doubleOf(Object bean, String method) {
        Object value = BSimDatabase.call(bean, method);
        return value instanceof Number
            ? Math.round(((Number) value).doubleValue() * 1000.0) / 1000.0
            : 0.0;
    }
}