// Measure the cost of the hot paths in the GhidraMCP plugin.
//
// Run headless:
//   analyzeHeadless <proj> MeasurePerf -import <binary> \
//       -scriptPath src/test/ghidra -postScript MeasurePerf
//
// The script reproduces what the plugin does per request, without needing the
// extension installed, and prints a RESULT line per measurement.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

public class MeasurePerf extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT = 60;
    private static final int PAGE_SIZE = 100;

    @Override
    public void run() throws Exception {
        List<Function> functions = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            functions.add(f);
        }
        if (functions.isEmpty()) {
            println("RESULT no-functions");
            return;
        }

        Function biggest = functions.get(0);
        Function median = functions.get(functions.size() / 2);
        for (Function f : functions) {
            if (f.getBody().getNumAddresses() > biggest.getBody().getNumAddresses()) {
                biggest = f;
            }
        }

        println("RESULT program=" + currentProgram.getName()
                + " functions=" + functions.size()
                + " biggest=" + biggest.getName()
                + " biggestBytes=" + biggest.getBody().getNumAddresses()
                + " median=" + median.getName()
                + " medianBytes=" + median.getBody().getNumAddresses());

        measureDecompile("median", median);
        measureDecompile("biggest", biggest);
        measureDisassembly(biggest);
        measureHexFormatting();
        measureSymbolListing();
    }

    /**
     * Materialising a DTO for every symbol versus only for the page.
     *
     * <p>Mirrors SymbolDto.from(): the same field reads, but only for the
     * symbols that land on the page.
     */
    private void measureSymbolListing() {
        int pageSize = 100;
        var symbols = currentProgram.getSymbolTable().getAllSymbols(true);

        long t0 = System.nanoTime();
        int total = 0;
        int sink = 0;
        for (var it = symbols.iterator(); it.hasNext(); ) {
            var sym = it.next();
            // The DTO read: name, address, type, flags, source.
            sink += sym.getName(true).length()
                    + sym.getAddress().toString().length()
                    + sym.getSymbolType().toString().length()
                    + (sym.isPrimary() ? 1 : 0)
                    + (sym.isExternal() ? 1 : 0)
                    + (sym.isGlobal() ? 1 : 0)
                    + (sym.getSource() != null ? sym.getSource().toString().length() : 0);
            total++;
        }
        long fullMs = (System.nanoTime() - t0) / 1_000_000;

        var symbols2 = currentProgram.getSymbolTable().getAllSymbols(true);
        long t1 = System.nanoTime();
        int index = 0;
        int pageSink = 0;
        for (var it = symbols2.iterator(); it.hasNext(); ) {
            var sym = it.next();
            if (index >= 0 && index < pageSize) {
                pageSink += sym.getName(true).length()
                        + sym.getAddress().toString().length()
                        + sym.getSymbolType().toString().length()
                        + (sym.isPrimary() ? 1 : 0)
                        + (sym.isExternal() ? 1 : 0)
                        + (sym.isGlobal() ? 1 : 0)
                        + (sym.getSource() != null ? sym.getSource().toString().length() : 0);
            }
            index++;
        }
        long pageMs = (System.nanoTime() - t1) / 1_000_000;

        println("RESULT symbolListing"
                + " totalSymbols=" + total
                + " fullMaterialiseMs=" + fullMs
                + " pageOnlyMs=" + pageMs
                + " pageSize=" + pageSize
                + " ratio=" + String.format("%.1fx", (double) fullMs / (double) Math.max(pageMs, 1))
                + " sink=" + (sink + pageSink));
    }

    /** Fresh DecompInterface + openProgram per call vs one reused interface. */
    private void measureDecompile(String label, Function fn) {
        int rounds = 3;

        long t0 = System.nanoTime();
        for (int i = 0; i < rounds; i++) {
            DecompInterface d = new DecompInterface();
            try {
                d.openProgram(currentProgram);
                d.decompileFunction(fn, DECOMPILE_TIMEOUT, TaskMonitor.DUMMY);
            } finally {
                d.dispose();
            }
        }
        long freshMs = (System.nanoTime() - t0) / 1_000_000;

        long t1 = System.nanoTime();
        DecompInterface reused = new DecompInterface();
        try {
            reused.openProgram(currentProgram);
            for (int i = 0; i < rounds; i++) {
                reused.decompileFunction(fn, DECOMPILE_TIMEOUT, TaskMonitor.DUMMY);
            }
        } finally {
            reused.dispose();
        }
        long reusedMs = (System.nanoTime() - t1) / 1_000_000;

        println("RESULT decompile-" + label
                + " freshPerCallMs=" + freshMs
                + " reusedMs=" + reusedMs
                + " rounds=" + rounds
                + " speedup=" + String.format("%.2fx", (double) freshMs / (double) Math.max(reusedMs, 1)));
    }

    /** Walking every instruction of a function vs walking one page of it. */
    private void measureDisassembly(Function fn) throws Exception {
        Listing listing = currentProgram.getListing();
        Address start = fn.getEntryPoint();
        Address end = fn.getBody().getMaxAddress();

        long t0 = System.nanoTime();
        int total = walkInstructions(listing, start, end, Integer.MAX_VALUE);
        long fullMs = (System.nanoTime() - t0) / 1_000_000;

        long t1 = System.nanoTime();
        int page = walkInstructions(listing, start, end, PAGE_SIZE);
        long pageMs = (System.nanoTime() - t1) / 1_000_000;

        println("RESULT disassembly"
                + " totalInstructions=" + total
                + " fullWalkMs=" + fullMs
                + " pageWalkMs=" + pageMs
                + " pageSize=" + PAGE_SIZE
                + " ratio=" + String.format("%.1fx", (double) fullMs / (double) Math.max(pageMs, 1)));
    }

    /** Mirrors DisassemblyInstructionDto.from() plus the operand rendering. */
    private int walkInstructions(Listing listing, Address start, Address end, int limit)
            throws Exception {
        int count = 0;
        for (Instruction i : listing.getInstructions(start, true)) {
            if (i.getAddress().compareTo(end) > 0) {
                break;
            }
            byte[] raw = new byte[i.getLength()];
            currentProgram.getMemory().getBytes(i.getAddress(), raw);
            StringBuilder sb = new StringBuilder();
            for (byte b : raw) {
                sb.append(String.format("%02X", b & 0xFF));
            }
            sb.append(i.getMnemonicString());
            int n = i.getNumOperands();
            for (int k = 0; k < n; k++) {
                sb.append(i.getDefaultOperandRepresentation(k));
            }
            count++;
            if (count >= limit) {
                break;
            }
        }
        return count;
    }

    /** String.format("%02X") vs a precomputed hex table, on the same byte count. */
    private void measureHexFormatting() {
        int iterations = 200_000;
        byte[] data = new byte[8];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 37);
        }

        long t0 = System.nanoTime();
        int sink = 0;
        for (int i = 0; i < iterations; i++) {
            for (byte b : data) {
                sink += String.format("%02X", b & 0xFF).length();
            }
        }
        long formatMs = (System.nanoTime() - t0) / 1_000_000;

        char[] hex = "0123456789ABCDEF".toCharArray();
        long t1 = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            for (byte b : data) {
                int v = b & 0xFF;
                sink += hex[v >>> 4];
                sink += hex[v & 0x0F];
            }
        }
        long tableMs = (System.nanoTime() - t1) / 1_000_000;

        println("RESULT hexFormat"
                + " stringFormatMs=" + formatMs
                + " hexTableMs=" + tableMs
                + " bytes=" + (iterations * data.length)
                + " speedup=" + String.format("%.1fx", (double) formatMs / (double) Math.max(tableMs, 1))
                + " sink=" + sink);
    }
}
