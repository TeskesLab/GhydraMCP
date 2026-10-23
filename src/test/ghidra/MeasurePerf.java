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
import java.util.Map;

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
        measureNativeCounts();
        measureSerialization();
        measureBlockModel();
        measureCfgWalk();
    }

    /**
     * The cost of the whole CFG walk: every basic block of the function and
     * its destinations, which is what the /cfg endpoint does per request.
     */
    private void measureCfgWalk() throws Exception {
        Function fn = null;
        long biggest = 0;
        for (var it = currentProgram.getFunctionManager().getFunctions(true); it.hasNext(); ) {
            var f = it.next();
            if (f.getBody().getNumAddresses() > biggest) {
                biggest = f.getBody().getNumAddresses();
                fn = f;
            }
        }
        if (fn == null) {
            return;
        }

        long t0 = System.nanoTime();
        int blocks = 0;
        int edges = 0;
        for (int round = 0; round < 5; round++) {
            var model = new ghidra.program.model.block.SimpleBlockModel(currentProgram, true);
            var funcBlock = model.getFirstCodeBlockContaining(
                fn.getEntryPoint(), ghidra.util.task.TaskMonitor.DUMMY);
            if (funcBlock == null) {
                continue;
            }
            var visited = new java.util.LinkedHashSet<ghidra.program.model.block.CodeBlock>();
            var queue = new java.util.LinkedList<ghidra.program.model.block.CodeBlock>();
            queue.add(funcBlock);
            while (!queue.isEmpty()) {
                var block = queue.poll();
                if (!visited.add(block)) {
                    continue;
                }
                blocks++;
                var destIter = block.getDestinations(ghidra.util.task.TaskMonitor.DUMMY);
                while (destIter.hasNext()) {
                    var ref = destIter.next();
                    var dest = ref.getDestinationBlock();
                    if (dest != null) {
                        edges++;
                        queue.add(dest);
                    }
                }
            }
        }
        long perCallMs = (System.nanoTime() - t0) / 1_000_000 / 5;

        println("RESULT cfgWalk"
                + " function=" + fn.getName()
                + " blocks=" + (blocks / 5)
                + " edges=" + (edges / 5)
                + " perCallMs=" + perCallMs);
    }

    /**
     * Do the native Ghidra counts agree with what the iterators yield?
     *
     * <p>The listing endpoints can only skip the full scan when the count the
     * client sees is the same as the number of items the scan would find.
     */
    private void measureNativeCounts() {
        int symbolCount = 0;
        for (var it = currentProgram.getSymbolTable().getAllSymbols(true); it.hasNext(); ) {
            it.next();
            symbolCount++;
        }
        int functionCount = 0;
        for (var it = currentProgram.getFunctionManager().getFunctions(true); it.hasNext(); ) {
            it.next();
            functionCount++;
        }
        long dataCount = 0;
        for (var it = currentProgram.getListing().getDefinedData(true); it.hasNext(); ) {
            it.next();
            dataCount++;
        }

        println("RESULT nativeCounts"
                + " symbols=" + symbolCount + " vs getNumSymbols=" + currentProgram.getSymbolTable().getNumSymbols()
                + " match=" + (symbolCount == currentProgram.getSymbolTable().getNumSymbols())
                + " functions=" + functionCount + " vs getFunctionCount=" + currentProgram.getFunctionManager().getFunctionCount()
                + " match=" + (functionCount == currentProgram.getFunctionManager().getFunctionCount())
                + " data=" + dataCount + " vs getNumDefinedData=" + currentProgram.getListing().getNumDefinedData()
                + " match=" + (dataCount == currentProgram.getListing().getNumDefinedData()));
    }

    /**
     * Pretty-printed JSON versus compact, and the per-item Gson round trip
     * that PaginatedResult does to attach the item links.
     */
    private void measureSerialization() {
        var symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        List<String> names = new ArrayList<>();
        for (var it = symbols.iterator(); it.hasNext(); ) {
            var sym = it.next();
            names.add(sym.getName(true) + "|" + sym.getAddress() + "|" + sym.getSymbolType()
                    + "|" + sym.isPrimary() + "|" + sym.isExternal() + "|" + sym.isGlobal());
            if (names.size() >= 100) {
                break;
            }
        }

        var compact = new com.google.gson.GsonBuilder().serializeNulls().create();
        var pretty = new com.google.gson.GsonBuilder().serializeNulls().setPrettyPrinting().create();

        // A realistic page item: the DTO fields plus the nested _links the
        // paginated result attaches.
        List<Map<String, Object>> page = new ArrayList<>();
        for (var it = currentProgram.getSymbolTable().getAllSymbols(true); it.hasNext(); ) {
            var sym = it.next();
            var item = new java.util.LinkedHashMap<String, Object>();
            item.put("address", sym.getAddress().toString());
            item.put("label", sym.getName(true));
            item.put("symbolType", sym.getSymbolType().toString());
            item.put("isPrimary", sym.isPrimary());
            item.put("isExternal", sym.isExternal());
            item.put("isGlobal", sym.isGlobal());
            item.put("source", sym.getSource() != null ? sym.getSource().toString() : null);
            item.put("_links", java.util.Map.of("self",
                java.util.Map.of("href", "/symbols/" + sym.getAddress(), "method", "GET")));
            page.add(item);
            if (page.size() >= 100) {
                break;
            }
        }

        long t0 = System.nanoTime();
        String compactJson = compact.toJson(page);
        long compactMs = (System.nanoTime() - t0) / 1_000_000;

        long t1 = System.nanoTime();
        String prettyJson = pretty.toJson(page);
        long prettyMs = (System.nanoTime() - t1) / 1_000_000;

        // The per-item round trip PaginatedResult does to flatten a record
        // into a map before adding "_links".
        var roundTrip = new com.google.gson.GsonBuilder()
            .setObjectToNumberStrategy(com.google.gson.ToNumberPolicy.LONG_OR_DOUBLE).create();
        List<Map<String, Object>> items = new ArrayList<>();
        for (var it = currentProgram.getSymbolTable().getAllSymbols(true); it.hasNext(); ) {
            var sym = it.next();
            items.add(new java.util.LinkedHashMap<>(java.util.Map.of(
                "name", sym.getName(true),
                "address", sym.getAddress().toString(),
                "type", sym.getSymbolType().toString())));
            if (items.size() >= 100) {
                break;
            }
        }
        long t2 = System.nanoTime();
        int sink = 0;
        for (var item : items) {
            Map<String, Object> asMap = roundTrip.fromJson(roundTrip.toJson(item), Map.class);
            sink += asMap.size();
        }
        long roundTripMs = (System.nanoTime() - t2) / 1_000_000;

        long t3 = System.nanoTime();
        int sink2 = 0;
        for (var item : items) {
            var tree = roundTrip.toJsonTree(item);
            sink2 += tree.isJsonObject() ? tree.getAsJsonObject().size() : 0;
        }
        long treeMs = (System.nanoTime() - t3) / 1_000_000;

        println("RESULT serialization"
                + " compactBytes=" + compactJson.length()
                + " prettyBytes=" + prettyJson.length()
                + " sizeRatio=" + String.format("%.2fx", (double) prettyJson.length() / (double) compactJson.length())
                + " compactMs=" + compactMs
                + " prettyMs=" + prettyMs
                + " roundTripMs=" + roundTripMs
                + " toJsonTreeMs=" + treeMs
                + " roundTripRatio=" + String.format("%.2fx", (double) roundTripMs / (double) Math.max(treeMs, 1))
                + " sink=" + (sink + sink2));
    }

    /** How much of the /cfg cost is the block model construction itself? */
    private void measureBlockModel() throws Exception {
        Function fn = null;
        long biggest = 0;
        for (var it = currentProgram.getFunctionManager().getFunctions(true); it.hasNext(); ) {
            var f = it.next();
            if (f.getBody().getNumAddresses() > biggest) {
                biggest = f.getBody().getNumAddresses();
                fn = f;
            }
        }
        if (fn == null) {
            return;
        }

        long t0 = System.nanoTime();
        for (int i = 0; i < 20; i++) {
            var model = new ghidra.program.model.block.SimpleBlockModel(currentProgram, true);
            model.getFirstCodeBlockContaining(fn.getEntryPoint(), ghidra.util.task.TaskMonitor.DUMMY);
        }
        long perCallMs = (System.nanoTime() - t0) / 1_000_000 / 20;

        long t1 = System.nanoTime();
        var model = new ghidra.program.model.block.SimpleBlockModel(currentProgram, true);
        for (int i = 0; i < 20; i++) {
            model.getFirstCodeBlockContaining(fn.getEntryPoint(), ghidra.util.task.TaskMonitor.DUMMY);
        }
        long reusedMs = (System.nanoTime() - t1) / 1_000_000 / 20;

        println("RESULT blockModel"
                + " function=" + fn.getName()
                + " newPerCallMs=" + perCallMs
                + " reusedMs=" + reusedMs
                + " constructionShare=" + String.format("%.1f%%",
                    100.0 * (perCallMs - reusedMs) / (double) Math.max(perCallMs, 1)));
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
