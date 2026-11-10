package eu.starsong.ghidra.service;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

/**
 * What changed between two versions of a binary, paired by signature.
 *
 * <p>{@code analysis_diff} compares two analyses by address and name: it is the
 * right answer for "what moved in the file". This is the complement, and it is
 * the thing a signature database is uniquely able to do: <b>pair functions by
 * shape</b>, so a function that was moved to another address (or compiled with a
 * different name) is reported as <em>the same function, relocated</em> instead of
 * as one removal plus one addition.
 *
 * <p>How a pair is decided, and said:
 * <ul>
 *   <li><b>a match is filtered to the other version, and the filter is applied
 *       inside the query</b> — BSim answers with the nearest functions of the
 *       whole corpus, so the executable has to be the one being compared
 *       against, or a pair would be invented from a third binary. The filter
 *       travels into BSim's SQL layer, so the match limit is spent on matches
 *       of that executable and not on the corpus;</li>
 *   <li><b>the similarity threshold is the caller's</b>, and every pair carries
 *       its number — this is a heuristic comparison, not an identity test;</li>
 *   <li><b>addresses are compared as numbers</b> — the two sides write them
 *       differently ("00401000" and "0x401000"), and comparing the text would
 *       report an unchanged function as moved;</li>
 *   <li><b>absence is stated, not implied</b>: a function with no match in the
 *       other version is listed as `not_found`, never silently dropped.</li>
 * </ul>
 *
 * <p>Cost is the honest part: one BSim query per function, measured at about
 * 0.2-0.8 s each, so the walk is bounded by {@code max_functions} and the answer
 * reports how many functions were <em>not</em> compared.
 */
public final class BSimDiffService {

    /** Functions compared when the caller does not say how many. */
    public static final int DEFAULT_MAX_FUNCTIONS = 25;

    /** A comparison bigger than this is a batch job, not a request. */
    public static final int MAX_FUNCTIONS_LIMIT = 500;

    /** How many matches BSim is asked for, per function. */
    private static final int MATCH_LIMIT = 5;

    /** The BSim query that asks for the nearest functions. */
    private static final String QUERY_NEAREST =
        "ghidra.features.bsim.query.protocol.QueryNearest";

    /** The BSim query that lists the executables the database holds. */
    private static final String QUERY_EXE_INFO =
        "ghidra.features.bsim.query.protocol.QueryExeInfo";

    /** The filter object that narrows a query to one executable. */
    private static final String BSIM_FILTER =
        "ghidra.features.bsim.query.protocol.BSimFilter";

    /** The base class of every BSim filter type. */
    private static final String BSIM_FILTER_TYPE =
        "ghidra.features.bsim.gui.filters.BSimFilterType";

    /** The filter type that matches on the name of the executable. */
    private static final String EXE_NAME_FILTER_TYPE =
        "ghidra.features.bsim.gui.filters.ExecutableNameBSimFilterType";

    private BSimDiffService() {
    }

    /**
     * Pair the open program's functions against another version in the database.
     *
     * @param program       the open program (version A)
     * @param otherExecutable the executable name recorded in the database (version B)
     * @param maxFunctions  how many functions of A to compare, 0 for the default
     * @param minSimilarity the floor for calling two functions a pair
     * @return the report: one row per function compared, with its class
     */
    public static Map<String, Object> diff(Program program, String otherExecutable,
            int maxFunctions, double minSimilarity) {
        Map<String, Object> data = new LinkedHashMap<>();
        long started = System.currentTimeMillis();
        if (otherExecutable == null || otherExecutable.isBlank()) {
            return BSimDatabase.failure(data, "BSIM_NO_TARGET",
                "name the executable to compare against (the name the database "
                    + "recorded when it was ingested)");
        }
        if (program == null) {
            return BSimDatabase.failure(data, "BSIM_NO_PROGRAM",
                "no program is open in this instance");
        }
        if (!BSimService.available()) {
            // The engine, not the database, is what is missing: sending the
            // reader to configure a database would not help.
            return BSimDatabase.failure(data, "BSIM_DISABLED",
                "this Ghidra build has no BSim query engine");
        }
        if (BSimService.database() == null || !BSimService.databaseExists()) {
            return BSimDatabase.failure(data, "BSIM_NO_DATABASE",
                "a comparison needs an ingested database: set -D"
                    + BSimService.PROPERTY_DATABASE + "=<path> and ingest both "
                    + "versions first");
        }

        int limit = maxFunctions <= 0 ? DEFAULT_MAX_FUNCTIONS
            : Math.min(maxFunctions, MAX_FUNCTIONS_LIMIT);
        double floor = minSimilarity <= 0 ? 0.8 : Math.min(minSimilarity, 1.0);
        String wanted = otherExecutable.trim();
        data.put("program", program.getName());
        data.put("other_executable", wanted);
        data.put("min_similarity", Double.valueOf(floor));

        // The filter is built once and applied to every query, so the answer
        // can say whether the narrowing was in force for the whole comparison.
        ExecutableFilter filter = buildExecutableFilter(wanted);

        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
        int discovered = 0;
        while (iterator.hasNext()) {
            Function function = iterator.next();
            discovered++;
            if (functions.size() < limit) {
                functions.add(function);
            }
        }
        data.put("discovered_functions", discovered);
        data.put("compared_functions", functions.size());
        data.put("not_compared", Math.max(0, discovered - functions.size()));

        List<Map<String, Object>> rows = new ArrayList<>();
        int moved = 0;
        int same = 0;
        int missing = 0;
        int noSignature = 0;
        int unknownAddress = 0;
        List<Map<String, Object>> failures = new ArrayList<>();
        for (Function function : functions) {
            Map<String, Object> queried = nearestMatches(program,
                function.getEntryPoint().toString(), floor, filter);
            if (!Boolean.TRUE.equals(queried.get("success"))) {
                // Two different things hide behind a failed query, and the report
                // must not confuse them: a function with no signature (a thunk,
                // an external, anything without a body) was never ingested, so
                // "not found in the other version" would be a lie about it.
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("function", function.getName());
                row.put("address", function.getEntryPoint().toString());
                String code = String.valueOf(queried.get("code"));
                if ("BSIM_NO_BODY".equals(code) || "BSIM_NO_FUNCTION".equals(code)) {
                    row.put("class", "no_signature");
                    row.put("reason", queried.get("reason"));
                    noSignature++;
                    rows.add(row);
                    continue;
                }
                row.put("code", queried.get("code"));
                row.put("reason", queried.get("reason"));
                failures.add(row);
                continue;
            }
            Map<String, Object> pair = bestPair(queried, wanted);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("function", function.getName());
            row.put("address", function.getEntryPoint().toString());
            if (pair == null) {
                row.put("class", "not_found");
                row.put("reason", "no function of " + wanted + " is at least "
                    + floor + " similar");
                missing++;
            } else {
                Object otherAddress = pair.get("address");
                if (otherAddress == null || String.valueOf(otherAddress).isBlank()) {
                    // Paired, but the address of the other side is unknown:
                    // calling that "moved" would claim a relocation nobody saw.
                    row.put("class", "unknown_address");
                    row.put("other", pair);
                    unknownAddress++;
                } else {
                    boolean relocated = !sameAddress(
                        function.getEntryPoint().toString(),
                        String.valueOf(otherAddress));
                    row.put("class", relocated ? "moved" : "same");
                    row.put("other", pair);
                    if (relocated) {
                        moved++;
                    } else {
                        same++;
                    }
                }
            }
            rows.add(row);
        }

        data.put("success", Boolean.TRUE);
        data.put("pairs", rows);
        data.put("same", same);
        data.put("moved", moved);
        data.put("not_found", missing);
        data.put("no_signature", noSignature);
        data.put("unknown_address", unknownAddress);
        data.put("query_failures", failures);
        // A comparison that could not query part of the program is not a
        // complete comparison, and must say so.
        data.put("complete", Boolean.valueOf(failures.isEmpty()));
        // The narrowing is reported after the walk, because a filter that could
        // not be attached to the query is a fact of the comparison and not of
        // the plan.
        data.put("executable_filter_applied", Boolean.valueOf(filter.isApplied()));
        data.put("other_executable_found", filter.found());
        if (!filter.isApplied()) {
            data.put("executable_filter_reason", filter.reason());
        }
        data.put("method", method(filter));
        data.put("seconds", BSimDatabase.secondsSince(started));
        return data;
    }

    /** What the comparison did, said honestly about the filter. */
    private static String method(ExecutableFilter filter) {
        String pairing = "Pairing by BSim similarity within the named "
            + "executable; a pair is a hypothesis, and every pair carries its "
            + "similarity. A function with no pair is listed, not dropped.";
        if (filter.isApplied()) {
            return pairing + " The executable filter is applied inside the "
                + "BSim query, so the match limit counts only matches of that "
                + "executable.";
        }
        return pairing + " The executable filter could NOT be applied ("
            + filter.reason() + "), so the match limit is spent on the whole "
            + "corpus and a match of the named executable can be missed.";
    }

    /**
     * The nearest functions of the wanted executable that look like one function.
     *
     * <p>The query is built here rather than asked of {@link BSimQueryService}
     * because the executable filter has to travel with the query: BSim applies
     * the filter in its SQL layer, so the match limit applies to the filtered
     * set. Everything is reflective for the reason {@link BSimIngestService}
     * gives: the BSim API is internal and moves between series.
     *
     * @param program the open program
     * @param address the entry point of the function being asked about
     * @param floor   the similarity floor
     * @param filter  the executable filter, or null when it could not be built
     * @return a payload shaped like {@code BSimQueryService.query}: {@code success}
     *         says whether the query ran, and the matches are in {@code matches}
     */
    private static Map<String, Object> nearestMatches(Program program, String address,
            double floor, ExecutableFilter filter) {
        Map<String, Object> data = new LinkedHashMap<>();
        String database = BSimService.database();
        if (!BSimService.available()) {
            return BSimDatabase.failure(data, "BSIM_DISABLED",
                "this Ghidra build has no BSim query engine");
        }
        if (database == null) {
            return BSimDatabase.failure(data, "BSIM_NO_DATABASE",
                "no signature database is configured");
        }
        if (program == null) {
            return BSimDatabase.failure(data, "BSIM_NO_PROGRAM",
                "no program is open in this instance");
        }

        Function function = GhidraSwing.runRead(() -> resolveFunction(program, address));
        if (function == null) {
            return BSimDatabase.failure(data, "BSIM_NO_FUNCTION",
                "no function at " + address);
        }
        if (function.getBody() == null || function.getBody().getNumAddresses() == 0) {
            return BSimDatabase.failure(data, "BSIM_NO_BODY",
                "the function has no body, so no signature can be made for it");
        }

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

            Class<?> queryClass = Class.forName(QUERY_NEAREST, true, loader);
            Object query = queryClass.getConstructor().newInstance();
            queryClass.getField("manage").set(query, description);
            queryClass.getField("thresh").set(query, Double.valueOf(floor));
            queryClass.getField("signifthresh").set(query, Double.valueOf(0.0));
            queryClass.getField("max").set(query, Integer.valueOf(MATCH_LIMIT));
            if (filter.isApplied()) {
                try {
                    queryClass.getField("bsimFilter").set(query, filter.bsimFilter());
                } catch (Throwable missing) {
                    // The narrowing is optional: without it the query still
                    // runs, only with the weaker, corpus-wide limit.
                    filter.disable("the BSim query has no filter field ("
                        + BSimDatabase.describe(BSimDatabase.unwrap(missing)) + ")");
                }
            }

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
            if (results != null) {
                for (Object result : results) {
                    Iterator<?> notes = iterate(result);
                    while (notes != null && notes.hasNext()
                            && matches.size() < MATCH_LIMIT) {
                        matches.add(describeNote(notes.next()));
                    }
                }
            }

            data.put("success", Boolean.TRUE);
            data.put("matches", matches);
            data.put("returned", Integer.valueOf(matches.size()));
            return data;
        } catch (Throwable failed) {
            Throwable cause = BSimDatabase.unwrap(failed);
            data.put("success", Boolean.FALSE);
            data.put("code", "BSIM_QUERY_FAILED");
            data.put("reason", BSimDatabase.describe(cause));
            return data;
        } finally {
            BSimDatabase.disposeQuietly(signatureGenerator);
            BSimDatabase.closeQuietly(connection);
        }
    }

    /**
     * The filter that narrows a query to one executable, and why it is missing
     * when it could not be built.
     *
     * <p>The filter is only used when the exact name the database recorded is
     * known: the BSim filter matches the executable name exactly, while the
     * answer compares names case-insensitively. Filtering on a name the
     * database does not hold would turn a case difference into a missing pair.
     */
    private static final class ExecutableFilter {

        /** The BSim filter instance, or null when it could not be built. */
        private final Object bsimFilter;

        /** Why the filter is missing, when it is. */
        private String reason;

        /** Does the database hold the executable that was asked for? */
        private final Boolean found;

        ExecutableFilter(Object bsimFilter, String reason, Boolean found) {
            this.bsimFilter = bsimFilter;
            this.reason = reason;
            this.found = found;
        }

        boolean isApplied() {
            return bsimFilter != null && reason == null;
        }

        Boolean found() {
            return found;
        }

        Object bsimFilter() {
            return bsimFilter;
        }

        String reason() {
            return reason == null ? "no reason was reported" : reason;
        }

        /** The narrowing is lost: the comparison runs without it. */
        void disable(String why) {
            this.reason = why;
        }
    }

    /**
     * Build the filter, resolving the exact name the database recorded first.
     *
     * <p>Everything is reflective: the BSim filter API is internal and has moved
     * between series, and a build that does not carry it must still answer the
     * comparison (with the old, weaker narrowing) instead of failing.
     */
    private static ExecutableFilter buildExecutableFilter(String wanted) {
        StoredName stored = storedExecutableName(wanted);
        if (stored.failure() != null) {
            // The database could not be asked, so nothing is claimed about it.
            return new ExecutableFilter(null, stored.failure(), null);
        }
        if (stored.name() == null) {
            return new ExecutableFilter(null,
                "the database holds no executable named '" + wanted
                    + "', so there was nothing to narrow the query to",
                Boolean.FALSE);
        }
        try {
            ClassLoader loader = BSimDatabase.loader();
            Class<?> filterClass = Class.forName(BSIM_FILTER, true, loader);
            Class<?> typeBase = Class.forName(BSIM_FILTER_TYPE, true, loader);
            Class<?> typeClass = Class.forName(EXE_NAME_FILTER_TYPE, true, loader);
            Object filter = filterClass.getConstructor().newInstance();
            Object type = typeClass.getConstructor().newInstance();
            filterClass.getMethod("addAtom", typeBase, String.class)
                .invoke(filter, type, stored.name());
            Object empty = filterClass.getMethod("isEmpty").invoke(filter);
            if (Boolean.TRUE.equals(empty)) {
                return new ExecutableFilter(null,
                    "the BSim filter refused the executable name '"
                        + stored.name() + "'", Boolean.TRUE);
            }
            return new ExecutableFilter(filter, null, Boolean.TRUE);
        } catch (Throwable missing) {
            return new ExecutableFilter(null,
                "this Ghidra build has no usable BSim executable filter ("
                    + BSimDatabase.describe(BSimDatabase.unwrap(missing)) + ")",
                Boolean.TRUE);
        }
    }

    /**
     * The name the database recorded for the wanted executable.
     *
     * <p>BSim matches the executable name exactly, so the name has to be the
     * one the database holds; the answer compares names case-insensitively, so
     * the name is looked up the way the database finds it (case-insensitively)
     * and the stored spelling is returned.
     */
    private static StoredName storedExecutableName(String wanted) {
        String database = BSimService.database();
        if (database == null) {
            return new StoredName(null, "no signature database is configured");
        }
        Map<String, Object> opened = new LinkedHashMap<>();
        Object connection = BSimDatabase.open(database, false, opened);
        if (connection == null) {
            return new StoredName(null,
                "the executable list could not be read from the database");
        }
        try {
            ClassLoader loader = BSimDatabase.loader();
            Class<?> queryClass = Class.forName(QUERY_EXE_INFO, true, loader);
            Object query = queryClass.getConstructor().newInstance();
            queryClass.getField("filterExeName").set(query, wanted);
            queryClass.getField("limit").set(query, Integer.valueOf(100));
            Object response = queryClass
                .getMethod("execute", Class.forName(BSimDatabase.FUNCTION_DATABASE,
                    true, loader))
                .invoke(query, connection);
            if (response == null) {
                return new StoredName(null,
                    "the executable list could not be read from the database");
            }
            Object records = fieldOf(response, "records");
            if (!(records instanceof Iterable)) {
                return new StoredName(null,
                    "the executable list could not be read from the database");
            }
            for (Object record : (Iterable<?>) records) {
                String name = (String) BSimDatabase.call(record, "getNameExec");
                if (name != null && name.equalsIgnoreCase(wanted)) {
                    return new StoredName(name, null);
                }
            }
            return new StoredName(null, null);
        } catch (Throwable unavailable) {
            // The listing is a convenience: without it the comparison still
            // runs, only without the narrowing.
            return new StoredName(null,
                "the executable list could not be read ("
                    + BSimDatabase.describe(BSimDatabase.unwrap(unavailable)) + ")");
        } finally {
            BSimDatabase.closeQuietly(connection);
        }
    }

    /**
     * The name the database recorded, or the reason it could not be read.
     *
     * <p>The two failures are different: an executable that is not in the
     * database is a fact about the database, and a listing that could not be
     * read is a fact about this build.
     */
    private static final class StoredName {

        /** The stored spelling, or null when the database holds no such name. */
        private final String name;

        /** Why the name could not be looked up, or null. */
        private final String failure;

        StoredName(String name, String failure) {
            this.name = name;
            this.failure = failure;
        }

        String name() {
            return name;
        }

        String failure() {
            return failure;
        }
    }

    /**
     * The best match that belongs to the other version, or null.
     *
     * @param queried         the answer of a query, with its matches
     * @param otherExecutable the executable the match has to belong to
     * @return the most similar match of that executable, or null
     */
    static Map<String, Object> bestPair(Map<String, Object> queried,
            String otherExecutable) {
        Object matches = queried.get("matches");
        if (!(matches instanceof List)) {
            return null;
        }
        return bestPair((List<?>) matches, otherExecutable);
    }

    /**
     * The most similar match of the wanted executable, or null.
     *
     * <p>The matches are the ones BSim answered with; the executable is checked
     * here as well because the query may have run without the filter.
     *
     * @param matches         the matches of a query
     * @param otherExecutable the executable the match has to belong to
     * @return the most similar match of that executable, or null
     */
    static Map<String, Object> bestPair(List<?> matches, String otherExecutable) {
        Map<String, Object> best = null;
        double bestSimilarity = -1.0;
        for (Object item : matches) {
            if (!(item instanceof Map)) {
                continue;
            }
            Map<?, ?> match = (Map<?, ?>) item;
            Object executable = match.get("executable");
            if (executable == null
                    || !String.valueOf(executable).equalsIgnoreCase(otherExecutable)) {
                continue;
            }
            double similarity = match.get("similarity") instanceof Number
                ? ((Number) match.get("similarity")).doubleValue() : 0.0;
            if (similarity > bestSimilarity) {
                bestSimilarity = similarity;
                best = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : match.entrySet()) {
                    best.put(String.valueOf(entry.getKey()), entry.getValue());
                }
            }
        }
        return best;
    }

    /**
     * Are these the same address?
     *
     * <p>The two sides do not write an address the same way: Ghidra writes the
     * entry point of a 32-bit function as "00401000" and BSim writes it as
     * "0x401000". Comparing the text says an unchanged function moved, so the
     * numbers are compared instead.
     *
     * @param a one side of the comparison
     * @param b the other side
     * @return true when both sides name the same address
     */
    static boolean sameAddress(String a, String b) {
        Long left = parseAddress(a);
        Long right = parseAddress(b);
        if (left != null && right != null) {
            return left.longValue() == right.longValue();
        }
        // A side that is not a hexadecimal address cannot be compared as a
        // number, and the text comparison is all that is left.
        return normalize(a).equals(normalize(b));
    }

    /**
     * The number an address names, or null when it is not one.
     *
     * <p>Both sides write an address in hexadecimal. The forms that have to be
     * read are the "0x" prefix, the zero padding of a fixed-width space, and
     * the address-space prefix Ghidra writes ("ram:00401000").
     *
     * @param address the address as one of the two sides wrote it
     * @return the value of the address, or null when it is not an address
     */
    static Long parseAddress(String address) {
        if (address == null) {
            return null;
        }
        String value = address.trim().toLowerCase();
        if (value.isEmpty()) {
            return null;
        }
        int colon = value.lastIndexOf(':');
        if (colon >= 0 && colon < value.length() - 1) {
            value = value.substring(colon + 1);
        }
        if (value.startsWith("0x")) {
            value = value.substring(2);
        }
        if (value.isEmpty()) {
            return null;
        }
        for (int i = 0; i < value.length(); i++) {
            char digit = value.charAt(i);
            boolean hex = (digit >= '0' && digit <= '9')
                || (digit >= 'a' && digit <= 'f');
            if (!hex) {
                return null;
            }
        }
        try {
            // Unsigned: a 64-bit address does not fit in a signed long, and two
            // addresses that are the same number are the same address.
            return Long.valueOf(Long.parseUnsignedLong(value, 16));
        } catch (NumberFormatException invalid) {
            return null;
        }
    }

    private static String normalize(String address) {
        String value = address == null ? "" : address.trim().toLowerCase();
        return value.startsWith("0x") ? value.substring(2) : value;
    }

    /** The function at an address, or null when there is none. */
    private static Function resolveFunction(Program program, String address) {
        try {
            Address target = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(address.trim());
            return program.getFunctionManager().getFunctionAt(target);
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

    /** One match, in the shape the answer uses. */
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
