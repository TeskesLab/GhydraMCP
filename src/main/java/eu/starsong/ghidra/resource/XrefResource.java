package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.XrefService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * REST resource for /xrefs endpoints.
 */
public class XrefResource implements Resource {

    private final XrefService xrefService;

    public XrefResource() {
        this.xrefService = new XrefService();
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/xrefs", ctx -> list(contextFactory.apply(ctx)));
        app.get("/xrefs/to/{address}", ctx -> getRefsTo(contextFactory.apply(ctx)));
        app.get("/xrefs/to-name/{name}", ctx -> getRefsToName(contextFactory.apply(ctx)));
        app.get("/xrefs/from/{address}", ctx -> getRefsFrom(contextFactory.apply(ctx)));
        app.get("/xrefs/calls/to/{address}", ctx -> getCallsTo(contextFactory.apply(ctx)));
        app.get("/xrefs/calls/from/{address}", ctx -> getCallsFrom(contextFactory.apply(ctx)));
    }

    /**
     * GET /xrefs - Query references with filters
     */
    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();

        String toAddr = ctx.queryParam("to_addr");
        String fromAddr = ctx.queryParam("from_addr");
        String refType = ctx.queryParam("type");

        if ((toAddr == null || toAddr.isEmpty()) && (fromAddr == null || fromAddr.isEmpty())) {
            throw new IllegalArgumentException("Either to_addr or from_addr query parameter is required");
        }

        // Collect enough refs to cover the requested page; collecting only `limit`
        // made every offset >= limit return an empty page.
        var pagination = ctx.pagination();
        int budget = (int) Math.min((long) pagination.offset() + pagination.limit(), 100_000L);
        List<XrefDto> xrefs = xrefService.getReferences(program, toAddr, fromAddr, refType, budget);

        var result = Paginator.paginate(xrefs, pagination, "/xrefs")
            .withItemLinks(xref -> Links.builder()
                .link("from", "/memory/{}", xref.fromAddress())
                .link("to", "/memory/{}", xref.toAddress())
                .build());

        Response response = result.toResponse(ctx.ctx(), ctx.port())
            .link("program", "/program");

        if (toAddr != null) {
            response.link("function", "/functions/{}", toAddr);
        }

        ctx.json(response.build());
    }

    /**
     * GET /xrefs/to/{address} - Get all references to an address
     */
    private void getRefsTo(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        List<XrefDto> xrefs = xrefService.getReferencesTo(program, address);

        var result = Paginator.paginate(xrefs, ctx.pagination(), "/xrefs/to/" + address);

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .link("target", "/functions/{}", address)
            .link("xrefs", "/xrefs")
            .build());
    }

    /**
     * GET /xrefs/to-name/{name} - Get the references to a symbol found by name
     *
     * <p>The name is resolved to the symbols that carry it and the references
     * to those symbols come back in one answer.
     */
    private void getRefsToName(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        var pagination = ctx.pagination();

        XrefService.NameReferences found = xrefService.getReferencesToName(program, name,
            pagination.offset(), pagination.limit());
        if (found.symbols().isEmpty()) {
            throw new NotFoundException("No symbol named '" + name
                + "' (a bare name matches every namespace; use the fully-qualified name, e.g. NS::"
                + name + ")", "SYMBOL_NOT_FOUND");
        }

        int total = found.total();
        int from = Math.min(pagination.offset(), total);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", name);
        result.put("symbols", found.symbols());
        result.put("references", found.references());
        result.put("total", total);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .meta("total", total)
            .meta("offset", from)
            .meta("limit", pagination.limit())
            .self("/xrefs/to-name/{}", name)
            .link("xrefs", "/xrefs")
            .build());
    }

    /**
     * GET /xrefs/from/{address} - Get all references from an address
     */
    private void getRefsFrom(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        List<XrefDto> xrefs = xrefService.getReferencesFrom(program, address);

        var result = Paginator.paginate(xrefs, ctx.pagination(), "/xrefs/from/" + address);

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .link("source", "/functions/{}", address)
            .link("xrefs", "/xrefs")
            .build());
    }

    /**
     * GET /xrefs/calls/to/{address} - Get call references to a function
     */
    private void getCallsTo(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        List<XrefDto> xrefs = xrefService.getCallsTo(program, address);

        var result = Paginator.paginate(xrefs, ctx.pagination(), "/xrefs/calls/to/" + address);

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .link("function", "/functions/{}", address)
            .link("xrefs", "/xrefs")
            .build());
    }

    /**
     * GET /xrefs/calls/from/{address} - Get call references from a function
     */
    private void getCallsFrom(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        List<XrefDto> xrefs = xrefService.getCallsFrom(program, address);

        var result = Paginator.paginate(xrefs, ctx.pagination(), "/xrefs/calls/from/" + address);

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .link("function", "/functions/{}", address)
            .link("xrefs", "/xrefs")
            .build());
    }
}
