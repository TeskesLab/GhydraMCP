package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.BSimIngestService;
import eu.starsong.ghidra.service.BSimApplyService;
import eu.starsong.ghidra.service.BSimDiffService;
import eu.starsong.ghidra.service.BSimQueryService;
import eu.starsong.ghidra.service.BSimService;
import io.javalin.Javalin;

import java.util.function.Function;

/**
 * What this instance can do with BSim (R1, discovery half).
 *
 * <p>One endpoint, {@code GET /bsim/status}, so a client can find out whether a
 * signature query is even possible before it asks for one: the feature may be
 * absent from the build, and the database is configuration. The answer is a
 * fact, not a guess — {@code ready} is true only when the engine is present and
 * a database is named, and {@code reason} names what is missing otherwise.
 */
public class BSimResource implements Resource {

    @Override
    public void register(Javalin app,
            Function<io.javalin.http.Context, GhidraContext> contextFactory) {
        app.get("/bsim/status", ctx -> status(contextFactory.apply(ctx)));
        app.post("/bsim/ingest", ctx -> ingest(contextFactory.apply(ctx)));
        app.get("/bsim/query", ctx -> query(contextFactory.apply(ctx)));
        app.post("/bsim/apply-names",
            ctx -> applyNames(contextFactory.apply(ctx)));
        app.get("/bsim/diff", ctx -> diff(contextFactory.apply(ctx)));
    }

    /**
     * Generate signatures for the open program and insert them into the
     * configured database.
     *
     * <p>The work is long (a decompile per function), so the answer is a report,
     * not a stream: how many functions were discovered, how many were scanned,
     * what BSim itself says it inserted, and why it stopped when it did.
     */
    private void ingest(GhidraContext ctx) {
        int maxFunctions = 0;
        String requested = ctx.ctx().queryParam("max_functions");
        if (requested != null && !requested.isBlank()) {
            try {
                maxFunctions = Integer.parseInt(requested.trim());
            } catch (NumberFormatException bad) {
                throw new IllegalArgumentException(
                    "max_functions must be a number, got: " + requested);
            }
        }
        boolean trackCallGraph = flag(ctx, "track_call_graph", false);
        java.util.Map<String, Object> data =
            BSimIngestService.ingest(ctx.program(), maxFunctions, trackCallGraph);
        respond(ctx, data, requested == null ? "/bsim/ingest"
            : "/bsim/ingest?max_functions=" + maxFunctions);
    }

    /**
     * Which stored functions look like one function of the open program.
     *
     * <p>A match carries BSim's similarity and significance numbers: it is a
     * lead, not an identification, and the answer says so.
     */
    private void query(GhidraContext ctx) {
        double minSimilarity = parseDouble(ctx, "min_similarity",
            BSimQueryService.DEFAULT_SIMILARITY);
        double minSignificance = parseDouble(ctx, "min_significance",
            BSimQueryService.DEFAULT_SIGNIFICANCE);
        int maxMatches = parseInt(ctx, "max_matches",
            BSimQueryService.DEFAULT_MAX_MATCHES);
        java.util.Map<String, Object> data = BSimQueryService.query(
            ctx.program(), ctx.ctx().queryParam("address"),
            ctx.ctx().queryParam("name"), maxMatches, minSimilarity,
            minSignificance);
        respond(ctx, data, "/bsim/query");
    }

    /**
     * Name a function after the stored one it most resembles.
     *
     * <p><b>Dry run by default.</b> A signature match is a heuristic, and a
     * wrong rename is a wrong map of the program; the caller has to ask for the
     * change with {@code dry_run=false}, and the answer carries the similarity
     * that justified it so the edit can be judged (and undone) later.
     */
    private void applyNames(GhidraContext ctx) {
        double minSimilarity = parseDouble(ctx, "min_similarity",
            BSimApplyService.MIN_APPLY_SIMILARITY);
        // Default true: the caller has to ask for the rename.
        boolean dryRun = flag(ctx, "dry_run", true);
        java.util.Map<String, Object> data = BSimApplyService.apply(
            ctx.program(), ctx.ctx().queryParam("address"),
            ctx.ctx().queryParam("name"), minSimilarity, dryRun);
        respond(ctx, data, "/bsim/apply-names");
    }

    /**
     * Pair the open program's functions against another version in the database.
     *
     * <p>The complement of `analysis_diff`: this pairs by signature, so a
     * function that moved address (or lost its name) is reported as the same
     * function relocated instead of one removal plus one addition.
     */
    private void diff(GhidraContext ctx) {
        double minSimilarity = parseDouble(ctx, "min_similarity", 0.8);
        int maxFunctions = parseInt(ctx, "max_functions",
            BSimDiffService.DEFAULT_MAX_FUNCTIONS);
        java.util.Map<String, Object> data = BSimDiffService.diff(
            ctx.program(), ctx.ctx().queryParam("other_executable"),
            maxFunctions, minSimilarity);
        respond(ctx, data, "/bsim/diff");
    }

    /**
     * Send a payload as a success or as a failure, consistently.
     *
     * <p>A BSim service reports its own failures in the payload (`success: false`
     * with a `code` and a `reason`) because a missing engine or function is a
     * normal state, not an exception. The envelope has to say the same thing: the
     * bridge and the CLI branch on it, and wrapping a failure in `Response.ok`
     * made every failed ingest read as "inserted 0 functions".
     */
    private void respond(GhidraContext ctx, java.util.Map<String, Object> data,
            String self) {
        Object code = data.get("code");
        Object reason = data.get("reason");
        if (Boolean.FALSE.equals(data.get("success")) && code != null) {
            failure(ctx, self, String.valueOf(code),
                reason == null ? "the operation did not complete"
                    : String.valueOf(reason));
            return;
        }
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data)
            .self(self)
            .link("status", "/bsim/status")
            .link("capabilities", "/capabilities")
            .build());
    }

    /**
     * Send one BSim failure, with the code written out at its call site.
     *
     * <p>A guard in `test_errors.py` requires every `Response.error` to carry a
     * literal code: a code assembled at runtime cannot be reviewed, and the client
     * branches on it. So each code this surface can answer with has its own branch
     * — which also makes the status each one deserves visible in one place.
     */
    private void failure(GhidraContext ctx, String self, String code, String reason) {
        switch (code) {
            case "BSIM_DISABLED":
                ctx.status(503);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_DISABLED", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_NO_DATABASE":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_NO_DATABASE", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_NO_PROGRAM":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_NO_PROGRAM", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_NO_FUNCTION":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_NO_FUNCTION", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_NO_BODY":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_NO_BODY", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_NO_TARGET":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_NO_TARGET", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_NO_MATCH":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_NO_MATCH", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_NO_NAME":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_NO_NAME", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_BELOW_THRESHOLD":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_BELOW_THRESHOLD", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_RENAME_REFUSED":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_RENAME_REFUSED", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_CREATE_FAILED":
                ctx.status(409);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_CREATE_FAILED", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_INIT_FAILED":
                ctx.status(409);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_INIT_FAILED", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_INSERT_FAILED":
                ctx.status(500);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_INSERT_FAILED", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_SCAN_FAILED":
                ctx.status(500);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_SCAN_FAILED", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_QUERY_FAILED":
                ctx.status(500);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_QUERY_FAILED", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_RENAME_FAILED":
                ctx.status(500);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_RENAME_FAILED", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_INGEST_FAILED":
                ctx.status(500);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_INGEST_FAILED", reason)
                    .self(self)
                    .build());
                return;
            default:
                ctx.status(500);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_INGEST_FAILED",
                        reason)
                    .self(self)
                    .build());
        }
    }

    /**
     * A strict boolean query parameter.
     *
     * <p>`Boolean.parseBoolean` answers `false` for anything that is not "true" —
     * including an empty value, "1" and "yes" — so a lenient parse of `dry_run`
     * silently **applies** a rename. Only the two words are accepted, and anything
     * else is a bad request.
     */
    private static boolean flag(GhidraContext ctx, String name, boolean fallback) {
        String raw = ctx.ctx().queryParam(name);
        if (raw == null) {
            return fallback;
        }
        String value = raw.trim().toLowerCase();
        if (value.equals("true")) {
            return true;
        }
        if (value.equals("false")) {
            return false;
        }
        throw new IllegalArgumentException(
            name + " must be true or false, got: " + raw);
    }

    private static int parseInt(GhidraContext ctx, String name, int fallback) {
        String raw = ctx.ctx().queryParam(name);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException bad) {
            throw new IllegalArgumentException(
                name + " must be a number, got: " + raw);
        }
    }

    private static double parseDouble(GhidraContext ctx, String name,
            double fallback) {
        String raw = ctx.ctx().queryParam(name);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            double parsed = Double.parseDouble(raw.trim());
            if (Double.isNaN(parsed) || Double.isInfinite(parsed)) {
                throw new NumberFormatException("not a finite number");
            }
            return parsed;
        } catch (NumberFormatException bad) {
            throw new IllegalArgumentException(
                name + " must be a number, got: " + raw);
        }
    }

    private void status(GhidraContext ctx) {
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), BSimService.status())
            .self("/bsim/status")
            .link("capabilities", "/capabilities")
            .build());
    }
}