package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Define raw image data types for inline rendering in Ghidra's Listing view.
 *
 * <p>POST /raw-image/define — creates a RawImage data item at the given address
 * with width, height, and pixel format settings.
 */
public class RawImageResource implements Resource {

    /** Bits-per-pixel for each format ordinal (must match RawImageFormatSettingsDefinition). */
    private static final int[] BPP = {16, 24, 32, 8, 16, 1, 2, 4, 8};

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.post("/raw-image/define", ctx -> define(contextFactory.apply(ctx)));
    }

    private void define(GhidraContext ctx) {
        Program program = ctx.requireProgram();
        DefineRequest req = ctx.bodyAsClass(DefineRequest.class);

        if (req.address == null || req.address.isEmpty()) {
            throw new IllegalArgumentException("address is required");
        }
        if (req.width <= 0 || req.height <= 0) {
            throw new IllegalArgumentException("width and height must be positive");
        }

        int formatOrdinal = parseFormat(req.format);
        boolean bigEndian = "big".equalsIgnoreCase(req.endian);
        int bpp = BPP[formatOrdinal];
        int byteLen = (req.width * req.height * bpp + 7) / 8;

        // Resolve the RawImage built-in data type
        DataType rawImageDt = BuiltInDataTypeManager.getDataTypeManager().getDataType("/RawImage");
        if (rawImageDt == null) {
            throw new IllegalStateException(
                "RawImage data type not found in BuiltInDataTypeManager");
        }

        var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        ghidra.program.model.address.Address addr;
        try {
            addr = addressSpace.getAddress(req.address);
        } catch (ghidra.program.model.address.AddressFormatException e) {
            throw new IllegalArgumentException("Invalid address: " + req.address, e);
        }
        if (addr == null) {
            throw new IllegalArgumentException("Invalid address: " + req.address);
        }

        final DataType dt = rawImageDt;
        final int finalByteLen = byteLen;
        final int finalFormat = formatOrdinal;
        final int finalWidth = req.width;
        final int finalHeight = req.height;

        Data created;
        try {
            created = TransactionHelper.executeInTransaction(program, "define_raw_image", () -> {
                Listing listing = program.getListing();
                listing.clearCodeUnits(addr, addr.add(finalByteLen - 1), false);
                Data data = listing.createData(addr, dt, finalByteLen);
                if (data != null) {
                    data.setValue("raw_image_width", finalWidth);
                    data.setValue("raw_image_height", finalHeight);
                    data.setValue("raw_image_format", finalFormat);
                    if (bigEndian) {
                        data.setValue("raw_image_endian", "big");
                    }
                }
                return data;
            });
        } catch (TransactionHelper.TransactionException e) {
            throw new RuntimeException("Transaction failed: " + e.getMessage(), e);
        }

        if (created == null) {
            throw new IllegalStateException("Failed to create raw image data at " + req.address);
        }

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

    private int parseFormat(String format) {
        if (format == null) return 0; // RGB565
        return switch (format.toUpperCase().replace("-", "_")) {
            case "RGB565", "" -> 0;
            case "RGB888" -> 1;
            case "ARGB8888" -> 2;
            case "RGB332" -> 3;
            case "ARGB4444" -> 4;
            case "1BPP", "1BPP_MONOCHROME" -> 5;
            case "2BPP", "2BPP_GRAYSCALE" -> 6;
            case "4BPP", "4BPP_GRAYSCALE" -> 7;
            case "8BPP", "8BPP_GRAYSCALE" -> 8;
            default -> throw new IllegalArgumentException("Unknown pixel format: " + format);
        };
    }

    private static class DefineRequest {
        public String address;
        public int width;
        public int height;
        public String format = "RGB565";
        public String endian = "little";
    }
}
