package eu.starsong.ghidra.service;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
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
        return query(program, address, name, maxMatches, minSimilarity,
            minSignificance, null);
    }

    /**
     * Query the database, narrowed to one executable when a filter is given.
     *
     * <p>The narrowing travels <b>inside</b> the query: BSim applies the filter in
     * its SQL layer, so the match limit is spent on the matches of that
     * executable and not on the whole corpus. A comparison against another
     * version needs that — otherwise five better matches of a third binary use
     * up the limit and the wanted pair is never seen.
     *
     * @param program       the open program
     * @param address       the function address, or null when a name is used
     * @param name          the function name, or null when an address is used
     * @param maxMatches    how many matches to return, 0 for the default
     * @param minSimilarity the similarity floor, 0 for the default
     * @param minSignificance the significance floor, 0 for the default
     * @param filter        the executable filter, or null for the whole corpus
     * @return the report; {@code success} says whether the query ran, and the
     *         matches are in {@code matches}
     */
    public static Map<String, Object> query(Program program, String address,
            String name, int maxMatches, double minSimilarity,
            double minSignificance, ExecutableFilter filter) {
        return queryInternal(program, address, name, maxMatches, minSimilarity,
            minSignificance, filter, null);
    }

    /**
     * Query with exact executable/architecture/compiler metadata and conjunctive executable categories.
     *
     * @param program the open program
     * @param address the function address, or null when a name is used
     * @param name the function name, or null when an address is used
     * @param maxMatches the existing match limit, 0 for the default
     * @param minSimilarity the existing similarity floor, 0 for the default
     * @param minSignificance the existing significance floor, 0 for the default
     * @param executable exact native executable name, or null when absent
     * @param architecture exact native architecture identifier, or null when absent
     * @param compiler exact native compiler identifier, or null when absent
     * @param categories JSON object mapping each category name to one string value, or null
     * @return the query report, including the actually applied {@code filters}
     */
    public static Map<String, Object> queryWithFilters(Program program, String address,
            String name, int maxMatches, double minSimilarity, double minSignificance,
            String executable, String architecture, String compiler, String categories) {
        BSimMetadataFilter metadata;
        try {
            metadata = BSimMetadataFilter.parse(executable, architecture, compiler, categories);
        } catch (IllegalArgumentException invalid) {
            return BSimDatabase.failure(new LinkedHashMap<>(), "BSIM_FILTER_INVALID",
                invalid.getMessage());
        }
        return queryInternal(program, address, name, maxMatches, minSimilarity,
            minSignificance, null, metadata);
    }

    private static Map<String, Object> queryInternal(Program program, String address,
            String name, int maxMatches, double minSimilarity, double minSignificance,
            ExecutableFilter filter, BSimMetadataFilter metadata) {
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

        Function function = GhidraSwing.runRead(
            () -> resolveFunction(program, address, name));
        if (function == null) {
            return BSimDatabase.failure(data, "BSIM_NO_FUNCTION",
                address != null
                    ? "no function at " + address
                    : "no function named " + name + " in this program");
        }
        boolean hasBody = GhidraSwing.runRead(() -> {
            data.put("program", program.getName());
            data.put("function", function.getName());
            data.put("address", function.getEntryPoint().toString());
            data.put("source_address", BSimMatchService.qualifiedAddress(function));
            data.put("source_modification", program.getModificationNumber());
            return function.getBody() != null && function.getBody().getNumAddresses() != 0;
        });
        if (!hasBody) {
            return BSimDatabase.failure(data, "BSIM_NO_BODY",
                "the function has no body, so no signature can be made for it");
        }

        data.put("database", database);
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
            data.put("available_categories", BSimMetadataFilter.availableCategories(databaseInfo));
            Object nativeMetadata = null;
            if (metadata != null && !metadata.isEmpty()) {
                try {
                    nativeMetadata = metadata.build(connection, databaseInfo);
                } catch (IllegalArgumentException invalid) {
                    return BSimDatabase.failure(data, "BSIM_FILTER_INVALID", invalid.getMessage());
                } catch (Throwable unsupported) {
                    return BSimDatabase.failure(data, "BSIM_FILTER_UNSUPPORTED",
                        "the database cannot apply the requested metadata filters ("
                            + BSimDatabase.describe(BSimDatabase.unwrap(unsupported)) + ")");
                }
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
            if (nativeMetadata != null) {
                try {
                    queryClass.getField("bsimFilter").set(query, nativeMetadata);
                } catch (Throwable unsupported) {
                    return BSimDatabase.failure(data, "BSIM_FILTER_UNSUPPORTED",
                        "this native QueryNearest cannot accept metadata filters");
                }
            }
            if (filter != null && filter.isApplied()) {
                try {
                    queryClass.getField("bsimFilter").set(query, filter.bsimFilter());
                } catch (Throwable missing) {
                    // The narrowing is optional: without it the query still runs,
                    // only with the weaker, corpus-wide limit. The reason is kept
                    // so the caller can say what happened.
                    filter.disable("the BSim query has no filter field ("
                        + BSimDatabase.describe(BSimDatabase.unwrap(missing)) + ")");
                }
            }

            Object response = queryClass.getMethod("execute", databaseClass)
                .invoke(query, connection);
            if (response == null) {
                return BSimDatabase.failure(data, "BSIM_QUERY_FAILED",
                    "the database refused the query");
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
            data.put("filters", metadata == null ? Map.of() : metadata.predicates());
            data.put("matches", matches);
            data.put("returned", matches.size());
            // The response carries what BSim itself considered; the loop above
            // only counts the notes it happened to walk before filling the page.
            Object considered = BSimDatabase.call(response, "getTotalCount");
            data.put("total_considered",
                considered instanceof Number ? ((Number) considered).intValue() : total);
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
            BSimDatabase.release(connection, database);
        }
    }


    // ==================================================== the executable filter
    //
    // The filter that narrows a query to one executable. It lives here, with
    // the query it narrows: a comparison against another version needs it, and
    // a second copy of the query machinery is a second copy of every bug in it.

    /**
     * The filter that narrows a query to one executable, and why it is missing
     * when it could not be built.
     *
     * <p>The filter is only used when the exact name the database recorded is
     * known: the BSim filter matches the executable name exactly, while the
     * answer compares names case-insensitively. Filtering on a name the
     * database does not hold would turn a case difference into a missing pair.
     */
    public static final class ExecutableFilter {

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

        /** Whether the narrowing is in force. */
        public boolean isApplied() {
            return bsimFilter != null && reason == null;
        }

        /** Whether the database holds the executable, or null when unknown. */
        public Boolean found() {
            return found;
        }

        /** Why the narrowing is not in force, when it is not. */
        public String reason() {
            return reason == null ? "no reason was reported" : reason;
        }

        /** The narrowing is lost: the comparison runs without it. */
        void disable(String why) {
            this.reason = why;
        }

        Object bsimFilter() {
            return bsimFilter;
        }
    }

    /**
     * Build the filter for an executable name, resolving the exact spelling
     * the database recorded first.
     *
     * <p>Everything is reflective: the BSim filter API is internal and has moved
     * between series, and a build that does not carry it must still answer the
     * comparison (with the old, weaker narrowing) instead of failing.
     *
     * @param wanted the name of the executable the query is about
     * @return the filter, or the reason it could not be built
     */
    public static ExecutableFilter executableFilter(String wanted) {
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
     * <p>BSim matches the executable name exactly, so the name has to be the one
     * the database holds; the answer compares names case-insensitively, so the
     * name is looked up the way the database finds it (case-insensitively) and
     * the stored spelling is returned.
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
            BSimDatabase.release(connection, database);
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
                match.put("executable_md5", BSimDatabase.call(exe, "getMd5"));
                match.put("architecture", BSimDatabase.call(exe, "getArchitecture"));
                match.put("compiler", BSimDatabase.call(exe, "getNameCompiler"));
                String repositoryUrl = BSimMatchService.safeRepositoryUrl(
                    BSimDatabase.call(exe, "getURLString"));
                match.put("repository_url", repositoryUrl);
                boolean referenceAvailable = repositoryUrl != null
                    && String.valueOf(match.get("executable_md5")).matches("(?i)[0-9a-f]{32}")
                    && !Boolean.TRUE.equals(BSimDatabase.call(exe, "isLibrary"));
                match.put("reference_available", referenceAvailable);
                if (!referenceAvailable) {
                    match.put("reference_reason",
                        "The indexed match has no usable repository URL and executable identity.");
                }
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