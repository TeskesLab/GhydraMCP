// Integration test for RawImageService against real Ghidra APIs.
//
// This runs under analyzeHeadless rather than the JUnit suite because constructing a
// live Program needs Ghidra's full runtime classpath (DB.jar and the Ghidra test
// framework), which the plugin's system-scoped dependencies in lib/ don't provide.
// Run it with:
//
//   analyzeHeadless <projectDir> RawImageTest -import <some-binary> \
//       -scriptPath src/test/ghidra -postScript TestRawImage
//
// Throws on the first failed assertion, so headless reports SCRIPT ERROR and a
// non-zero exit — usable as a CI gate.

import eu.starsong.ghidra.service.RawImageService;
import eu.starsong.ghidra.service.RawImageService.CleanupReport;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

public class TestRawImage extends GhidraScript {

    private int checks = 0;

    private void check(String label, boolean cond, Object detail) {
        checks++;
        println((cond ? "PASS " : "FAIL ") + label + (cond ? "" : "  <<< ") + detail);
        if (!cond) {
            throw new AssertionError(label + " (was: " + detail + ")");
        }
    }

    /**
     * A free address well past the start of the program, derived from the program's own
     * layout so this works for any binary (image bases vary wildly — winmm.dll sits at
     * 0x180000000, a typical EXE at 0x400000).
     */
    private Address addr(Program p, long offset) throws Exception {
        Address a = p.getMinAddress().add(0x4000 + offset);
        if (!p.getMemory().contains(a)) {
            throw new IllegalStateException("test address not in memory: " + a);
        }
        return a;
    }

    /** Create plain byte data, clearing anything already there so we don't hit a code conflict. */
    private void putBytes(Program p, Address a, int len) throws Exception {
        Listing listing = p.getListing();
        listing.clearCodeUnits(a, a.add(len - 1), false);
        listing.createData(a, ByteDataType.dataType, len);
    }

    @Override
    public void run() throws Exception {
        Program p = currentProgram;
        check("program is changeable", p.isChangeable(), p.getName());

        RawImageService svc = new RawImageService();

        // --- define: byte math follows the pixel format's bits-per-pixel ---

        Address a1 = addr(p, 0x00);
        Data d1 = svc.define(p, a1.toString(), 4, 4, "RGB565", "little");
        check("define 4x4 RGB565 (16bpp) is 32 bytes", d1 != null && d1.getLength() == 32,
                d1 == null ? "null" : d1.getLength());

        Address a2 = addr(p, 0x100);
        Data d2 = svc.define(p, a2.toString(), 2, 2, "ARGB8888", "big");
        check("define 2x2 ARGB8888 (32bpp) is 16 bytes", d2 != null && d2.getLength() == 16,
                d2 == null ? "null" : d2.getLength());

        Address a3 = addr(p, 0x200);
        Data d3 = svc.define(p, a3.toString(), 8, 1, "1bpp", "little");
        check("define 8x1 1bpp is 1 byte", d3 != null && d3.getLength() == 1,
                d3 == null ? "null" : d3.getLength());

        // --- cleanup: single, idempotent, sweep ---

        CleanupReport r1 = svc.cleanup(p, a1.toString());
        check("cleanup single removes exactly one", r1.addresses().size() == 1, r1.addresses().size());
        check("cleanup single reports freed bytes", r1.bytes() == 32, r1.bytes());

        CleanupReport r2 = svc.cleanup(p, a1.toString());
        check("cleanup is idempotent", r2.addresses().size() == 0, r2.addresses().size());

        CleanupReport r3 = svc.cleanup(p, null);
        check("sweep clears the remaining images", r3.addresses().size() >= 2, r3.addresses().size());

        CleanupReport r4 = svc.cleanup(p, null);
        check("sweep is idempotent", r4.addresses().size() == 0, r4.addresses().size());

        // --- empty/blank address means "sweep everything", matching the CLI's --all ---

        Address a4 = addr(p, 0x300);
        svc.define(p, a4.toString(), 2, 2, "RGB565", "little");
        CleanupReport r5 = svc.cleanup(p, "");
        check("blank address sweeps the program", r5.addresses().size() >= 1, r5.addresses().size());

        // --- guard: never clear a data item we didn't create ---

        Address a5 = addr(p, 0x400);
        putBytes(p, a5, 16);
        try {
            svc.cleanup(p, a5.toString());
            check("cleanup refuses non-RawImage data", false, "no exception thrown");
        }
        catch (IllegalArgumentException e) {
            check("cleanup refuses non-RawImage data", true, e.getMessage());
            check("refusal names the actual type", e.getMessage().contains("/byte"),
                    e.getMessage());
        }
        p.getListing().clearCodeUnits(a5, a5.add(15), false);

        // --- input validation: these must be IllegalArgumentException so the HTTP
        //     layer maps them to 400 rather than 500 ---

        check("define rejects non-positive width",
                throwsIllegalArgument(() -> svc.define(p, a1.toString(), 0, 4, "RGB565", "little")),
                "width=0");
        check("define rejects unknown format",
                throwsIllegalArgument(() -> svc.define(p, a1.toString(), 4, 4, "NOPE", "little")),
                "format=NOPE");
        check("define rejects empty address",
                throwsIllegalArgument(() -> svc.define(p, "", 4, 4, "RGB565", "little")),
                "address=\"\"");
        check("cleanup rejects unparseable address",
                throwsIllegalArgument(() -> svc.cleanup(p, "zzzz")),
                "address=zzzz");

        println("RawImageService: " + checks + " checks passed");
    }

    private interface Op {
        void run() throws Exception;
    }

    private boolean throwsIllegalArgument(Op op) {
        try {
            op.run();
            return false;
        }
        catch (IllegalArgumentException e) {
            return true;
        }
        catch (Exception e) {
            println("    (unexpected " + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
            return false;
        }
    }
}