package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.RawImageService;
import eu.starsong.ghidra.service.RawImageService.CleanupReport;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Raw image data types for inline rendering in Ghidra's Listing view.
 *
 * <ul>
 *   <li>POST /raw-image/define — create a RawImage data item at an address with width, height,
 *       and pixel format settings.</li>
 *   <li>POST /raw-image/cleanup — remove RawImage data items, one by address or all at once.</li>
 * </ul>
 *
 * All Ghidra work (and the transactions around it) lives in {@link RawImageService}; this class
 * only validates the request shape and builds the HATEOAS response.
 */
public class RawImageResource implements Resource {

    /** Cap on how many cleared addresses we echo back, so a whole-program sweep stays bounded. */
    private static final int MAX_REPORTED_ADDRESSES = 100;

    private final RawImageService rawImageService;

    public RawImageResource() {
        this(new RawImageService());
    }

    public RawImageResource(RawImageService rawImageService) {
        this.rawImageService = rawImageService;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.post("/raw-image/define", ctx -> define(contextFactory.apply(ctx)));
        app.post("/raw-image/cleanup", ctx -> cleanup(contextFactory.apply(ctx)));
    }

    private void define(GhidraContext ctx) {
        Program program = ctx.requireProgram();
        DefineRequest req = ctx.bodyAsClass(DefineRequest.class);

        if (req.address == null || req.address.isEmpty()) {
            throw new IllegalArgumentException("address is required");
        }

        Data created = rawImageService.define(program, req.address, req.width, req.height,
            req.format, req.endian);
        if (created == null) {
            throw new IllegalStateException("Failed to create raw image data at " + req.address);
        }

        int byteLen = created.getLength();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", req.address);
        result.put("width", req.width);
        result.put("height", req.height);
        result.put("format", req.format);
        result.put("bytes", byteLen);
        result.put("message", "RawImage defined: " + req.width + "x" + req.height + " " + req.format
            + " at " + req.address + " (" + byteLen + " bytes)");

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/raw-image/define")
            .link("memory", "/memory/{}", req.address)
            .build());
    }

    private void cleanup(GhidraContext ctx) {
        Program program = ctx.requireProgram();
        CleanupRequest req = ctx.bodyAsClass(CleanupRequest.class);

        boolean sweepAll = req.all || req.address == null || req.address.isEmpty();
        CleanupReport report = rawImageService.cleanup(program, sweepAll ? null : req.address);

        List<Address> cleared = report.addresses();
        boolean truncated = cleared.size() > MAX_REPORTED_ADDRESSES;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("mode", sweepAll ? "all" : "single");
        if (!sweepAll) {
            result.put("address", req.address);
        }
        result.put("removed", cleared.size());
        result.put("bytes", report.bytes());
        result.put("addresses", cleared.subList(0, Math.min(cleared.size(), MAX_REPORTED_ADDRESSES))
            .stream().map(Address::toString).toList());
        result.put("addressesTruncated", truncated);
        result.put("message", cleared.isEmpty()
            ? "No RawImage data to clean up"
            : "Cleared " + cleared.size() + " RawImage data item(s), " + report.bytes() + " bytes");

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/raw-image/cleanup")
            .linkWithMethod("define", "/raw-image/define", "POST")
            .build());
    }

    private static class DefineRequest {
        public String address;
        public int width;
        public int height;
        public String format = "RGB565";
        public String endian = "little";
    }

    private static class CleanupRequest {
        public String address;
        public boolean all;
    }
}