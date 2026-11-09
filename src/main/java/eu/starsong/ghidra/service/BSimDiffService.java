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
 *   <li><b>a match is filtered to the other version</b> — BSim answers with the
 *       nearest functions in the whole corpus, so the executable has to be the
 *       one being compared against, or a pair would be invented from a third
 *       binary;</li>
 *   <li><b>the similarity threshold is the caller's</b>, and every pair carries
 *       its number — this is a heuristic comparison, not an identity test;</li>
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
        if (!BSimService.available() || BSimService.database() == null
                || !BSimService.databaseExists()) {
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
        List<Map<String, Object>> failures = new ArrayList<>();
        for (Function function : functions) {
            Map<String, Object> queried = BSimQueryService.query(program,
                function.getEntryPoint().toString(), null, 5, floor, 0.0);
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
                String otherAddress = String.valueOf(pair.get("address"));
                boolean relocated = !sameAddress(
                    function.getEntryPoint().toString(), otherAddress);
                row.put("class", relocated ? "moved" : "same");
                row.put("other", pair);
                if (relocated) {
                    moved++;
                } else {
                    same++;
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
        data.put("query_failures", failures);
        data.put("method", "Pairing by BSim similarity within the named "
            + "executable; a pair is a hypothesis, and every pair carries its "
            + "similarity. A function with no pair is listed, not dropped.");
        data.put("seconds", BSimDatabase.secondsSince(started));
        return data;
    }

    /** The best match that belongs to the other version, or null. */
    private static Map<String, Object> bestPair(Map<String, Object> queried,
            String otherExecutable) {
        Object matches = queried.get("matches");
        if (!(matches instanceof List)) {
            return null;
        }
        Map<String, Object> best = null;
        double bestSimilarity = -1.0;
        for (Object item : (List<?>) matches) {
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

    private static boolean sameAddress(String a, String b) {
        return normalize(a).equals(normalize(b));
    }

    private static String normalize(String address) {
        String value = address == null ? "" : address.trim().toLowerCase();
        return value.startsWith("0x") ? value.substring(2) : value;
    }
}