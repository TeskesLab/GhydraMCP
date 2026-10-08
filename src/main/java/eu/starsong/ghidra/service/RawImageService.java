package eu.starsong.ghidra.service;

import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;

/**
 * Service for RawImage data items — creates them and removes them again.
 *
 * <p>Owns the transactions; callers never touch the listing directly. Both operations run
 * entirely inside {@link TransactionHelper#executeInTransaction}, which executes on the EDT, so
 * reading the listing inside the transaction is safe and the target set cannot drift between
 * the read and the write.
 */
public class RawImageService {

    /** Path of the RawImage built-in data type, used to recognise our own data items on cleanup. */
    private static final String RAW_IMAGE_PATH = "/RawImage";

    /** Bits-per-pixel for each format ordinal (must match RawImageFormatSettingsDefinition). */
    private static final int[] BPP = {16, 24, 32, 8, 16, 1, 2, 4, 8};

    /**
     * Create a RawImage at {@code addressStr}, clearing whatever occupies the span first.
     *
     * @return the created data, or null if Ghidra declined to create it
     * @throws IllegalArgumentException            bad address, dimensions, or format (surfaces as 400)
     * @throws TransactionHelper.TransactionException the write could not be committed (surfaces as 409)
     */
    public Data define(Program program, String addressStr, int width, int height,
                       String format, String endian) {

        if (width <= 0 || height <= 0) {
            throw new IllegalArgumentException("width and height must be positive");
        }
        int formatOrdinal = parseFormat(format);
        int byteLen = (width * height * BPP[formatOrdinal] + 7) / 8;
        boolean bigEndian = "big".equalsIgnoreCase(endian);

        DataType rawImageDt = resolveRawImageType();
        Address addr = requireAddress(program, addressStr);

        final int finalByteLen = byteLen;
        final int finalFormat = formatOrdinal;
        final int finalWidth = width;
        final int finalHeight = height;

        return TransactionHelper.executeInTransaction(program, "define_raw_image", () -> {
            Listing listing = program.getListing();
            listing.clearCodeUnits(addr, addr.add(finalByteLen - 1), false);
            Data data = listing.createData(addr, rawImageDt, finalByteLen);
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
    }

    /**
     * Remove RawImage data items — the one at {@code addressStr}, or every RawImage in the
     * program when {@code addressStr} is null/blank. Clearing a code unit leaves the bytes
     * undefined again.
     *
     * @throws IllegalArgumentException            bad address, or non-RawImage data at that address
     * @throws TransactionHelper.TransactionException the write could not be committed
     */
    public CleanupReport cleanup(Program program, String addressStr) {
        boolean sweepAll = addressStr == null || addressStr.isEmpty();
        if (!sweepAll) {
            // Validate before opening a transaction so a bad address fails fast.
            requireAddress(program, addressStr);
        }

        return TransactionHelper.executeInTransaction(program, "Cleanup Raw Images", () -> {
            List<Address> targets = sweepAll ? findAllRawImages(program) : findRawImageAt(program, addressStr);
            long bytes = 0;
            for (Address target : targets) {
                CodeUnit cu = program.getListing().getDefinedDataAt(target);
                if (cu != null) {
                    bytes += cu.getLength();
                    program.getListing().clearCodeUnits(target, cu.getMaxAddress(), false);
                }
            }
            return new CleanupReport(targets, bytes);
        });
    }

    /** Immutable tally produced inside the transaction, read after it commits. */
    public record CleanupReport(List<Address> addresses, long bytes) {
    }

    private static DataType resolveRawImageType() {
        DataType dt = BuiltInDataTypeManager.getDataTypeManager().getDataType(RAW_IMAGE_PATH);
        if (dt == null) {
            throw new IllegalStateException("RawImage data type not found in BuiltInDataTypeManager");
        }
        return dt;
    }

    private static Address requireAddress(Program program, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) {
            throw new IllegalArgumentException("address is required");
        }
        // Resolve via GhidraUtil so bare-hex, 0x-prefixed, and space::offset forms all work,
        // matching every other endpoint.
        Address addr = GhidraUtil.resolveAddress(program, addressStr);
        if (addr == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        return addr;
    }

    /** Every RawImage data item in the program, in listing order. Runs on the EDT. */
    private static List<Address> findAllRawImages(Program program) {
        List<Address> found = new ArrayList<>();
        DataIterator it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data data = it.next();
            if (isRawImage(data.getDataType())) {
                found.add(data.getAddress());
            }
        }
        return found;
    }

    /**
     * The single RawImage at {@code addressStr}. Throws if something else (or nothing) is
     * defined there, so the caller never silently clears an unrelated data item.
     */
    private static List<Address> findRawImageAt(Program program, String addressStr) {
        Address addr = GhidraUtil.resolveAddress(program, addressStr);
        CodeUnit cu = program.getListing().getDefinedDataAt(addr);
        if (cu == null) {
            Msg.info(RawImageService.class, "cleanup: no data defined at " + addr);
            return List.of();
        }
        if (!(cu instanceof Data data)) {
            throw new IllegalArgumentException("No Data defined at " + addr + " (found a code unit)");
        }
        if (!isRawImage(data.getDataType())) {
            DataType dt = data.getDataType();
            throw new IllegalArgumentException("Data at " + addr + " is not a RawImage (found "
                + (dt != null ? dt.getPathName() : "undefined") + ")");
        }
        return List.of(data.getAddress());
    }

    private static boolean isRawImage(DataType dt) {
        return dt != null && RAW_IMAGE_PATH.equals(dt.getPathName());
    }

    private static int parseFormat(String format) {
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
}