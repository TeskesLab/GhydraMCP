package eu.starsong.ghidra.util;

import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.IntSupplier;

/**
 * Caches values derived from a program and drops them when the program
 * changes.
 *
 * <p>The listing endpoints report {@code meta.total}: the number of items the
 * endpoint can return. Ghidra's own counters do not answer that question —
 * {@code getNumSymbols()} (28 993) and {@code getFunctionCount()} (4 444)
 * disagree with what their iterators yield (29 587 and 3 333) on a binary with
 * 29 587 symbols, and using them would change the total the client sees. The
 * count has to be walked, and walking it on every request is what this cache
 * removes: the walk happens once per program state, not once per page.
 */
public class ProgramCache implements DomainObjectListener {

    private static final ProgramCache SHARED = new ProgramCache();

    /** How many function graphs are kept before the cache is dropped. */
    private static final int MAX_CFG_ENTRIES = 64;

    /** The process-wide cache. */
    public static ProgramCache shared() {
        return SHARED;
    }

    private final Map<String, Integer> counts = new ConcurrentHashMap<>();
    private final Map<Address, Cfg> cfgs = new ConcurrentHashMap<>();
    private volatile Program currentProgram;

    /**
     * The control flow graph of a function.
     *
     * @param blocks the basic blocks, in walk order
     * @param edges  the flow between them
     */
    public record Cfg(List<Map<String, Object>> blocks, List<Map<String, Object>> edges) {
    }

    /**
     * The cached count for {@code key}, computing it with {@code counter} the
     * first time it is asked for.
     *
     * @param program the program the count belongs to
     * @param key     identifies the collection being counted
     * @param counter walks the collection; runs on the caller's thread
     */
    public int count(Program program, String key, IntSupplier counter) {
        ensureProgram(program);
        Integer cached = counts.get(key);
        if (cached != null) {
            return cached;
        }
        int value = counter.getAsInt();
        counts.put(key, value);
        return value;
    }

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        // Any program change can change a count or a graph; drop them conservatively.
        counts.clear();
        cfgs.clear();
    }

    /**
     * The cached control flow graph of a function, or null when it is not
     * cached.
     *
     * <p>Walking the blocks of a function and their edges is the whole cost of
     * the CFG endpoint — 24 ms for a function with 1079 blocks — and the graph
     * only changes when the program does.
     */
    public Cfg getCfg(Program program, Address entry) {
        ensureProgram(program);
        return cfgs.get(entry);
    }

    /** Caches the control flow graph of a function. */
    public void putCfg(Program program, Address entry, Cfg cfg) {
        ensureProgram(program);
        if (cfgs.size() >= MAX_CFG_ENTRIES) {
            cfgs.clear();
        }
        cfgs.put(entry, cfg);
    }

    private void ensureProgram(Program program) {
        if (program == currentProgram) {
            return;
        }
        synchronized (this) {
            if (program == currentProgram) {
                return;
            }
            counts.clear();
            cfgs.clear();
            if (currentProgram != null) {
                currentProgram.removeListener(this);
            }
            currentProgram = program;
            if (currentProgram != null) {
                currentProgram.addListener(this);
            }
        }
    }
}
