package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.InspectService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.function.Function;

/**
 * REST resource for /inspect endpoints.
 *
 * <p>One call that says what an address is, instead of four calls that each
 * say one piece of it.
 */
public class InspectResource implements Resource {

    private final InspectService inspectService;

    public InspectResource() {
        this.inspectService = new InspectService();
    }

    public InspectResource(InspectService inspectService) {
        this.inspectService = inspectService;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/inspect/address/{address}", ctx -> address(contextFactory.apply(ctx)));
    }

    /**
     * GET /inspect/address/{address} - What is at this address
     */
    private void address(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        var context = inspectService.context(program, address);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), context)
            .self("/inspect/address/{}", address)
            .link("memory", "/memory/{}", address)
            .link("xrefs_to", "/xrefs?to_addr={}", address)
            .link("xrefs_from", "/xrefs?from_addr={}", address)
            .link("program", "/program")
            .build());
    }
}
