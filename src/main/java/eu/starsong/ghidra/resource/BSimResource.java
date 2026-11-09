package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
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
    }

    private void status(GhidraContext ctx) {
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), BSimService.status())
            .self("/bsim/status")
            .link("capabilities", "/capabilities")
            .build());
    }
}