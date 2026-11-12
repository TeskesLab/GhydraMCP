package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.BSimIngestService;
import eu.starsong.ghidra.service.BSimApplyService;
import eu.starsong.ghidra.service.BSimDiffService;
import eu.starsong.ghidra.service.BSimQueryService;
import eu.starsong.ghidra.service.BSimMultiQueryService;
import eu.starsong.ghidra.service.BSimService;
import eu.starsong.ghidra.service.BSimMatchService;
import eu.starsong.ghidra.service.BSimMatchApplyService;
import io.javalin.Javalin;

import java.util.function.Function;
import java.util.function.Consumer;

/** Profile-scoped BSim operations; credentials are resolved only by the worker. */
public class BSimResource implements Resource {
    private final BSimMatchService matches = new BSimMatchService();
    private final BSimMatchApplyService explicitApply = new BSimMatchApplyService(matches);

    @Override
    public void register(Javalin app,
            Function<io.javalin.http.Context, GhidraContext> contextFactory) {
        app.get("/bsim/status", ctx -> scoped(contextFactory.apply(ctx), null, this::status));
        app.post("/bsim/ingest", ctx -> scoped(contextFactory.apply(ctx), "ingest", this::ingest));
        app.get("/bsim/query", ctx -> scoped(contextFactory.apply(ctx), "query", this::query));
        app.get("/bsim/overview", ctx -> scoped(contextFactory.apply(ctx), "query", c -> multiQuery(c, true)));
        app.get("/bsim/batch-query", ctx -> scoped(contextFactory.apply(ctx), "query", c -> multiQuery(c, false)));
        app.post("/bsim/apply-names",
            ctx -> scoped(contextFactory.apply(ctx), "query", this::applyNames));
        app.get("/bsim/diff", ctx -> scoped(contextFactory.apply(ctx), "query", this::diff));
        app.get("/bsim/matches/{match_id}",
            ctx -> scoped(contextFactory.apply(ctx), "query", this::inspectMatch));
        app.get("/bsim/matches/{match_id}/validate",
            ctx -> scoped(contextFactory.apply(ctx), "query", this::validateMatch));
        app.get("/bsim/matches/{match_id}/selection",
            ctx -> scoped(contextFactory.apply(ctx), "query", this::selection));
        app.post("/bsim/matches/{match_id}/prepare-apply",
            ctx -> scoped(contextFactory.apply(ctx), "query", this::prepareApply));
        app.post("/bsim/matches/{match_id}/apply",
            ctx -> scoped(contextFactory.apply(ctx), "query", this::applyMatch));
    }

    private void scoped(GhidraContext ctx, String permission,
            Consumer<GhidraContext> operation) {
        ConnectionProfiles.withProfile(ctx.ctx().queryParam("profile"), "bsim",
            permission, selected -> {
                operation.accept(ctx);
                return null;
            });
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
        // Absent means "the caller did not say", and the service applies its
        // default (5 000). `max_functions=0` is an explicit "everything", which is
        // a decision the caller makes rather than one the default makes for them.
        int maxFunctions = -1;
        String requested = ctx.ctx().queryParam("max_functions");
        if (requested != null && !requested.isBlank()) {
            try {
                maxFunctions = Integer.parseInt(requested.trim());
            } catch (NumberFormatException bad) {
                throw new IllegalArgumentException(
                    "max_functions must be a number, got: " + requested);
            }
            if (maxFunctions < 0) {
                throw new IllegalArgumentException(
                    "max_functions must be 0 (everything) or a positive number, got: "
                        + requested);
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
     *
     * <p>Optional executable, architecture and compiler parameters are exact native values.
     * categories is one JSON object of category-name/string-value predicates; all filters
     * are ANDed inside the native query before max_matches is consumed.
     */
    private void query(GhidraContext ctx) {
        for (String filter : java.util.List.of("executable", "architecture", "compiler", "categories")) {
            if (ctx.ctx().queryParams(filter).size() > 1) {
                throw new IllegalArgumentException("Only one " + filter + " filter parameter is allowed");
            }
        }
        double minSimilarity = parseDouble(ctx, "min_similarity",
            BSimQueryService.DEFAULT_SIMILARITY);
        double minSignificance = parseDouble(ctx, "min_significance",
            BSimQueryService.DEFAULT_SIGNIFICANCE);
        int maxMatches = parseInt(ctx, "max_matches",
            BSimQueryService.DEFAULT_MAX_MATCHES);
        var program = ctx.program();
        java.util.Map<String, Object> data = BSimQueryService.queryWithFilters(
            program, ctx.ctx().queryParam("address"),
            ctx.ctx().queryParam("name"), maxMatches, minSimilarity,
            minSignificance, ctx.ctx().queryParam("executable"),
            ctx.ctx().queryParam("architecture"), ctx.ctx().queryParam("compiler"),
            ctx.ctx().queryParam("categories"));
        matches.register(program, data);
        respond(ctx, data, "/bsim/query");
    }

    private void multiQuery(GhidraContext ctx, boolean overview) {
        String self = overview ? "/bsim/overview" : "/bsim/batch-query";
        java.util.Map<String, Object> data;
        var program = ctx.program();
        Object consumer = new Object();
        boolean pinned = program != null && eu.starsong.ghidra.util.GhidraSwing.runUninterruptibly(
            () -> program.addConsumer(consumer));
        try {
            try {
                if (ctx.ctx().queryParamMap().values().stream().anyMatch(values -> values.size() != 1))
                    throw new IllegalArgumentException("Only one value per query parameter is allowed");
                int offset = strictInt(ctx, "offset", 0);
                int count = strictInt(ctx, "max_functions", 50);
                int limit = strictInt(ctx, "max_matches", overview ? 1 : 3);
                double similarity = strictDouble(ctx, "min_similarity", 0.7);
                double significance = strictDouble(ctx, "min_significance", 0);
                String stampText = ctx.ctx().queryParam("expected_modification");
                Long stamp = stampText == null ? null : Long.valueOf(stampText);
                data = overview
                    ? BSimMultiQueryService.overview(program, offset, count, limit, similarity, significance,
                        stamp, ctx.queryParam("expected_program"), ctx.queryParam("executable"), ctx.queryParam("architecture"),
                        ctx.queryParam("compiler"), ctx.queryParam("categories"))
                    : BSimMultiQueryService.batch(program, ctx.queryParam("addresses"), limit,
                        similarity, significance, stamp, ctx.queryParam("expected_program"), ctx.queryParam("executable"),
                        ctx.queryParam("architecture"), ctx.queryParam("compiler"), ctx.queryParam("categories"));
            } catch (IllegalArgumentException invalid) {
                failure(ctx, self, "BSIM_BATCH_INVALID", invalid.getMessage());
                return;
            }
            if (Boolean.FALSE.equals(data.get("success"))) { respond(ctx, data, self); return; }
            matches.registerMulti(program, data);
            eu.starsong.ghidra.util.GhidraSwing.runRead(() -> {
                if (program == null || program.isClosed()
                        || program.getModificationNumber() != ((Number) data.get("source_modification")).longValue())
                    throw new eu.starsong.ghidra.connection.ConnectionException("BSIM_MATCH_STALE", 409,
                        "Source changed before the response; restart the query");
                respond(ctx, data, self);
                return null;
            });
        } finally {
            if (pinned) eu.starsong.ghidra.util.GhidraSwing.runUninterruptibly(() -> { program.release(consumer); return null; });
        }
    }

    private static int strictInt(GhidraContext ctx, String name, int fallback) {
        String text = ctx.queryParam(name);
        return text == null ? fallback : Integer.parseInt(text);
    }

    private static double strictDouble(GhidraContext ctx, String name, double fallback) {
        String text = ctx.queryParam(name);
        return text == null ? fallback : Double.parseDouble(text);
    }

    private void inspectMatch(GhidraContext ctx) {
        String id = ctx.ctx().pathParam("match_id");
        respond(ctx, matches.inspect(ctx.program(), id,
            parseInt(ctx, "max_code_lines", 1000)), "/bsim/matches/" + id);
    }

    private void validateMatch(GhidraContext ctx) {
        String id = ctx.ctx().pathParam("match_id");
        respond(ctx, matches.validate(ctx.program(), id), "/bsim/matches/" + id + "/validate");
    }
    private void selection(GhidraContext ctx) {
        String id = ctx.ctx().pathParam("match_id");
        respond(ctx, matches.selection(ctx.program(), id), "/bsim/matches/" + id + "/selection");
    }

    private static java.util.Map<?, ?> explicitBody(GhidraContext ctx, String key) {
        if (!java.util.Set.of("profile").containsAll(ctx.ctx().queryParamMap().keySet())
                || ctx.ctx().queryParamMap().values().stream().anyMatch(values -> values.size() != 1)) {
            throw new IllegalArgumentException("Only one profile query parameter is allowed");
        }
        java.util.Map<?, ?> body = ctx.bodyAsClass(java.util.Map.class);
        if (body == null || !body.keySet().equals(java.util.Set.of(key))) {
            throw new IllegalArgumentException("The JSON body must contain only " + key);
        }
        return body;
    }

    private void prepareApply(GhidraContext ctx) {
        Object reference = explicitBody(ctx, "reference").get("reference");
        if (!(reference instanceof java.util.Map<?, ?> exported)) {
            throw new IllegalArgumentException("reference must be the complete native export object");
        }
        String id = ctx.ctx().pathParam("match_id");
        respond(ctx, explicitApply.prepare(ctx.program(), id, exported, ctx::program),
            "/bsim/matches/" + id + "/prepare-apply");
    }

    private void applyMatch(GhidraContext ctx) {
        Object token = explicitBody(ctx, "apply_token").get("apply_token");
        if (!(token instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException("apply_token must be a nonblank string");
        }
        String id = ctx.ctx().pathParam("match_id");
        respond(ctx, explicitApply.apply(ctx.program(), id, text, ctx::program), "/bsim/matches/" + id + "/apply");
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
        String profile = ctx.queryParam("profile");
        String statusPath = "/bsim/status" + (profile == null || profile.isBlank() ? ""
            : "?profile=" + java.net.URLEncoder.encode(profile, java.nio.charset.StandardCharsets.UTF_8));
        Response response = Response.ok(ctx.ctx(), ctx.port(), data)
            .self(self)
            .link("status", statusPath)
            .link("capabilities", "/capabilities");
        if ("overview".equals(data.get("mode")) && data.get("next_offset") != null) {
            java.util.Map<String, String> parameters = new java.util.LinkedHashMap<>();
            for (String key : java.util.List.of("profile", "executable", "architecture", "compiler", "categories")) {
                String value = ctx.queryParam(key);
                if (value != null) parameters.put(key, value);
            }
            for (String key : java.util.List.of("max_functions", "max_matches", "min_similarity", "min_significance"))
                parameters.put(key, String.valueOf(data.get(key)));
            parameters.put("offset", String.valueOf(data.get("next_offset")));
            parameters.put("expected_modification", String.valueOf(data.get("source_modification")));
            parameters.put("expected_program", String.valueOf(data.get("source_program_id")));
            String query = parameters.entrySet().stream().map(entry ->
                java.net.URLEncoder.encode(entry.getKey(), java.nio.charset.StandardCharsets.UTF_8) + "="
                + java.net.URLEncoder.encode(entry.getValue(), java.nio.charset.StandardCharsets.UTF_8))
                .collect(java.util.stream.Collectors.joining("&"));
            response.link("next", "/bsim/overview?" + query);
        }
        ctx.json(response.build());
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
            case "BSIM_BATCH_INVALID":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_BATCH_INVALID", reason)
                    .self(self).build());
                return;
            case "BSIM_MATCH_STALE":
                ctx.status(409);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_MATCH_STALE", reason)
                    .self(self).build());
                return;
            case "BSIM_FILTER_INVALID":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_FILTER_INVALID", reason)
                    .self(self)
                    .build());
                return;
            case "BSIM_FILTER_UNSUPPORTED":
                ctx.status(400);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_FILTER_UNSUPPORTED", reason)
                    .self(self)
                    .build());
                return;
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
            case "BSIM_INCOMPLETE_INGEST":
                // The database holds a partial ingest of this executable and
                // BSim keys an executable by its fingerprint, so the request
                // cannot be completed as it stands: 409 says "the current state
                // forbids this", which is what it is. The reason says what the
                // store holds and how to get past it.
                ctx.status(409);
                ctx.json(Response.error(ctx.ctx(), ctx.port(), "BSIM_INCOMPLETE_INGEST", reason)
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