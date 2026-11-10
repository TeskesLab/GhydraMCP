package eu.starsong.ghidra.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
        // The query service owns it: the filter travels inside the query, which
        // is where BSim applies it.
        BSimQueryService.ExecutableFilter filter =
            BSimQueryService.executableFilter(wanted);

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
            Map<String, Object> queried = BSimQueryService.query(program,
                function.getEntryPoint().toString(), null, MATCH_LIMIT, floor,
                0.0, filter);
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
    private static String method(BSimQueryService.ExecutableFilter filter) {
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

}
