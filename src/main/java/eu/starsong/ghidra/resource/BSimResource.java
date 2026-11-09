package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.BSimIngestService;
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
        boolean trackCallGraph = Boolean.parseBoolean(
            ctx.ctx().queryParam("track_call_graph") == null ? "false"
                : ctx.ctx().queryParam("track_call_graph").trim());
        java.util.Map<String, Object> data =
            BSimIngestService.ingest(ctx.program(), maxFunctions, trackCallGraph);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data)
            .self(requested == null ? "/bsim/ingest"
                : "/bsim/ingest?max_functions=" + maxFunctions)
            .link("status", "/bsim/status")
            .link("capabilities", "/capabilities")
            .build());
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
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data)
            .self("/bsim/query")
            .link("status", "/bsim/status")
            .link("ingest", "/bsim/ingest")
            .build());
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
            return Double.parseDouble(raw.trim());
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