package eu.starsong.ghidra.service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import eu.starsong.ghidra.util.TransactionHelper;

/**
 * Applying a signature match to the program: name a function after the stored
 * one it most resembles.
 *
 * <p>The query half already answers "which stored function is this?". This is
 * the step that acts on the answer — and the one that needs care, because it
 * writes:
 *
 * <ul>
 *   <li><b>dry run by default.</b> The route reports what it <em>would</em> do
 *       unless the caller asks for the change; a wrong rename is a wrong map of
 *       the program, and the tool is a heuristic.</li>
 *   <li><b>a threshold, always.</b> Nothing is applied below the similarity the
 *       caller asked for, and the applied match's numbers travel back with the
 *       name so the change can be judged later.</li>
 *   <li><b>one transaction.</b> The rename goes through
 *       {@code TransactionHelper}, so it is undoable in Ghidra like any other
 *       edit, and a failure rolls back.</li>
 *   <li><b>no rename when it would change nothing</b>: a function already named
 *       like its match is reported as such rather than rewritten.</li>
 * </ul>
 */
public final class BSimApplyService {

    /** A match below this is not worth naming a function after. */
    public static final double MIN_APPLY_SIMILARITY = 0.8;

    private BSimApplyService() {
    }

    /**
     * Query the database and name the function after its best match.
     *
     * @param program      the open program
     * @param address      the function address, or null when a name is used
     * @param name         the function name, or null when an address is used
     * @param minSimilarity the floor for applying, 0 for {@link #MIN_APPLY_SIMILARITY}
     * @param dryRun       report the change without making it (default true)
     * @return the report: the match used, whether the name was applied, and why
     *         not when it was not
     */
    public static Map<String, Object> apply(Program program, String address,
            String name, double minSimilarity, boolean dryRun) {
        Map<String, Object> data = new LinkedHashMap<>();
        double floor = minSimilarity <= 0 ? MIN_APPLY_SIMILARITY
            : Math.min(minSimilarity, 1.0);
        data.put("dry_run", Boolean.valueOf(dryRun));
        data.put("min_similarity", Double.valueOf(floor));

        Map<String, Object> queried = BSimQueryService.query(program, address,
            name, 10, floor, 0.0);
        if (!Boolean.TRUE.equals(queried.get("success"))) {
            // The query's own report says what is wrong (no database, no
            // function, a refused query); pass it through instead of inventing
            // a second taxonomy.
            data.putAll(queried);
            data.put("dry_run", Boolean.valueOf(dryRun));
            data.put("min_similarity", Double.valueOf(floor));
            return data;
        }

        data.put("function", queried.get("function"));
        data.put("address", queried.get("address"));
        data.put("database", queried.get("database"));

        List<?> matches = (List<?>) queried.get("matches");
        if (matches == null || matches.isEmpty()) {
            data.put("success", Boolean.FALSE);
            data.put("code", "BSIM_NO_MATCH");
            data.put("reason", "no stored function is at least " + floor
                + " similar, so nothing was applied");
            return data;
        }
        // BSim does not promise the matches are ordered, and the rename must
        // follow the *most* similar one, not the first one in the list.
        Map<?, ?> match = null;
        double best = -1.0;
        for (Object item : matches) {
            if (!(item instanceof Map)) {
                continue;
            }
            Map<?, ?> candidate = (Map<?, ?>) item;
            double score = asDouble(candidate.get("similarity"));
            if (score > best) {
                best = score;
                match = candidate;
            }
        }
        if (match == null) {
            data.put("success", Boolean.FALSE);
            data.put("code", "BSIM_NO_MATCH");
            data.put("reason", "the query returned no usable match");
            return data;
        }
        String matchedName = asString(match.get("function"));
        double similarity = best;
        data.put("match", match);
        if (matchedName == null || matchedName.isBlank()) {
            data.put("success", Boolean.FALSE);
            data.put("code", "BSIM_NO_NAME");
            data.put("reason", "the best match carries no function name");
            return data;
        }
        if (similarity < floor) {
            data.put("success", Boolean.FALSE);
            data.put("code", "BSIM_BELOW_THRESHOLD");
            data.put("reason", "the best match is " + similarity
                + " similar, below the " + floor + " floor");
            return data;
        }

        Function function = GhidraSwing.runRead(
            () -> resolve(program, address, name));
        if (function == null) {
            data.put("success", Boolean.FALSE);
            data.put("code", "BSIM_NO_FUNCTION");
            data.put("reason", "the function could not be resolved after the query");
            return data;
        }
        String current = function.getName();
        data.put("from", current);
        data.put("to", matchedName);
        if (current.equals(matchedName)) {
            data.put("success", Boolean.TRUE);
            data.put("applied", Boolean.FALSE);
            data.put("already_named", Boolean.TRUE);
            data.put("reason", "the function already carries the matched name");
            return data;
        }

        if (dryRun) {
            data.put("success", Boolean.TRUE);
            data.put("applied", Boolean.FALSE);
            data.put("would_rename", Boolean.TRUE);
            data.put("reason", "dry run: pass dry_run=false to apply");
            return data;
        }

        try {
            final String wanted = matchedName;
            TransactionHelper.executeInTransaction(
                program, "BSim: name after a signature match", () -> {
                    function.setName(wanted, SourceType.USER_DEFINED);
                    return null;
                });
        } catch (RuntimeException failed) {
            // The helper wraps everything into a RuntimeException (its
            // TransactionException for a refused transaction), so a rename that
            // Ghidra refuses arrives here with the reason in the cause chain.
            String reason = BSimDatabase.describe(
                failed.getCause() == null ? failed : failed.getCause());
            boolean refused = reason.contains("DuplicateName")
                || reason.contains("InvalidInput")
                || reason.toLowerCase().contains("already exists");
            data.put("success", Boolean.FALSE);
            data.put("code", refused ? "BSIM_RENAME_REFUSED" : "BSIM_RENAME_FAILED");
            data.put("reason", reason);
            return data;
        }

        data.put("success", Boolean.TRUE);
        data.put("applied", Boolean.TRUE);
        data.put("similarity", Double.valueOf(similarity));
        data.put("reason", "renamed from the signature match; undo in Ghidra if "
            + "the match is wrong");
        return data;
    }

    private static Function resolve(Program program, String address, String name) {
        try {
            if (address != null && !address.isBlank()) {
                return program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(address.trim()));
            }
            if (name == null || name.isBlank()) {
                return null;
            }
            var functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function candidate = functions.next();
                if (name.equals(candidate.getName())) {
                    return candidate;
                }
            }
            return null;
        } catch (Exception invalid) {
            return null;
        }
    }

    private static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static double asDouble(Object value) {
        return value instanceof Number ? ((Number) value).doubleValue() : 0.0;
    }
}