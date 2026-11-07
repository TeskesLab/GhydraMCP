package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.CallPathDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Service for advanced analysis operations (call graphs, callers, callees).
 * Contains the call-graph traversal business logic extracted from AnalysisResource.
 *
 * <p>The DB-reading traversals are wrapped in {@link GhidraSwing#runRead} so the whole
 * read+build runs on the EDT. {@code runRead} is reentrant, so the nested
 * {@link XrefService} calls (which run their own reads) execute inline.
 */
public class AnalysisService {

    /** How many hops a call-path search may take. */
    private static final int MAX_CALL_PATH_DEPTH = 16;

    /** How many functions a call-path search may walk through. */
    private static final int MAX_CALL_PATH_NODES = 5000;

    private final FunctionService functionService;
    private final XrefService xrefService;

    public AnalysisService() {
        this.functionService = new FunctionService();
        this.xrefService = new XrefService();
    }

    public AnalysisService(FunctionService functionService, XrefService xrefService) {
        this.functionService = functionService;
        this.xrefService = xrefService;
    }

    /**
     * Result of a call-graph traversal: the built data map plus the resolved entry point.
     */
    public record CallGraphResult(Map<String, Object> data, String entryPoint) {
    }

    /**
     * Build the call graph for a function, resolving the start function by address or name.
     *
     * @param byAddress if true, {@code lookup} is an address; otherwise a function name
     * @param lookup    the address or name to resolve the start function
     */
    public CallGraphResult callGraph(Program program, boolean byAddress, String lookup, int depth, String direction) {
        // The traversal dereferences live Function objects (FunctionSummaryDto.from,
        // getEntryPoint, recursive xref walks). Run the whole read+build on the EDT.
        return GhidraSwing.runRead(() -> {
            Function startFn = byAddress
                ? functionService.requireFunctionByAddress(program, lookup)
                : functionService.requireFunctionByName(program, lookup);

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("root", FunctionSummaryDto.from(startFn));
            data.put("depth", depth);
            data.put("direction", direction);

            String entryPoint = startFn.getEntryPoint().toString();
            Set<String> visited = new HashSet<>();
            visited.add(entryPoint);

            if ("callers".equals(direction) || "both".equals(direction)) {
                List<Map<String, Object>> callers = buildCallTree(program, startFn, depth, true, visited);
                data.put("callers", callers);
            }

            if ("callees".equals(direction) || "both".equals(direction)) {
                visited.clear();
                visited.add(entryPoint);
                List<Map<String, Object>> callees = buildCallTree(program, startFn, depth, false, visited);
                data.put("callees", callees);
            }

            return new CallGraphResult(data, entryPoint);
        });
    }

    /**
     * Get the functions that call the function at the given address.
     */
    public List<FunctionSummaryDto> callers(Program program, String address) {
        return GhidraSwing.runRead(() -> {
            functionService.requireFunctionByAddress(program, address);

            List<XrefDto> callXrefs = xrefService.getCallsTo(program, address);

            Set<String> seen = new HashSet<>();
            List<FunctionSummaryDto> list = new ArrayList<>();

            for (XrefDto xref : callXrefs) {
                if (xref.fromFunctionAddress() != null && !seen.contains(xref.fromFunctionAddress())) {
                    seen.add(xref.fromFunctionAddress());
                    Function callerFn = functionService.findByAddress(program, xref.fromFunctionAddress());
                    if (callerFn != null) {
                        list.add(FunctionSummaryDto.from(callerFn));
                    }
                }
            }
            return list;
        });
    }

    /**
     * Get the functions called by the function at the given address.
     */
    public List<FunctionSummaryDto> callees(Program program, String address) {
        return GhidraSwing.runRead(() -> {
            Function fn = functionService.requireFunctionByAddress(program, address);

            // Calls are made from instructions inside the body, not the entry address.
            List<XrefDto> callXrefs = xrefService.getCallsFromFunction(program, fn);

            Set<String> seen = new HashSet<>();
            List<FunctionSummaryDto> list = new ArrayList<>();

            for (XrefDto xref : callXrefs) {
                if (xref.toFunctionAddress() != null && !seen.contains(xref.toFunctionAddress())) {
                    seen.add(xref.toFunctionAddress());
                    Function calleeFn = functionService.findByAddress(program, xref.toFunctionAddress());
                    if (calleeFn != null) {
                        list.add(FunctionSummaryDto.from(calleeFn));
                    }
                }
            }
            return list;
        });
    }

    /**
     * Find the shortest call path from one function to another.
     *
     * <p>The call graph says who calls whom; this answers the question an
     * agent actually asks when it holds the two ends: how does A reach B.
     *
     * <p>The search is a breadth-first walk over the call edges, so the path
     * it returns is the shortest one Ghidra knows about. It runs on the EDT
     * like the rest of the graph traversals, and it is bounded: the depth
     * limit and the visited cap keep one pathological program from turning
     * the request into a freeze.
     *
     * @param fromRef  the starting function, by address or by name
     * @param toRef    the function being looked for, by address or by name
     * @param maxDepth how many hops the search may take
     */
    public CallPathDto callPath(Program program, String fromRef, String toRef, int maxDepth) {
        int depth = Math.max(1, Math.min(maxDepth, MAX_CALL_PATH_DEPTH));

        return GhidraSwing.runRead(() -> {
            Function from = resolveFunction(program, fromRef);
            Function to = resolveFunction(program, toRef);

            FunctionSummaryDto fromDto = FunctionSummaryDto.from(from);
            FunctionSummaryDto toDto = FunctionSummaryDto.from(to);

            String fromAddr = from.getEntryPoint().toString();
            String toAddr = to.getEntryPoint().toString();

            if (fromAddr.equals(toAddr)) {
                return new CallPathDto(true, 0, depth, fromDto, toDto, List.of(fromDto), 1, null);
            }

            Deque<CallPathNode> queue = new ArrayDeque<>();
            Map<String, String> parent = new HashMap<>();
            Set<String> visited = new HashSet<>();

            queue.add(new CallPathNode(from, fromAddr, 0));
            visited.add(fromAddr);

            int explored = 0;
            List<FunctionSummaryDto> path = null;
            boolean truncated = false;

            while (!queue.isEmpty() && path == null) {
                CallPathNode current = queue.poll();
                explored++;

                if (current.depth() >= depth) {
                    continue;
                }

                for (String calleeAddr : calleeAddresses(program, current.function())) {
                    if (calleeAddr.equals(toAddr)) {
                        path = buildPath(program, parent, current.address(), fromDto, toDto);
                        break;
                    }
                    if (!visited.add(calleeAddr)) {
                        continue;
                    }
                    if (visited.size() >= MAX_CALL_PATH_NODES) {
                        truncated = true;
                        continue;
                    }
                    Function callee = functionService.findByAddress(program, calleeAddr);
                    if (callee == null) {
                        continue;
                    }
                    parent.put(calleeAddr, current.address());
                    queue.add(new CallPathNode(callee, calleeAddr, current.depth() + 1));
                }
            }

            if (path != null) {
                return new CallPathDto(true, path.size() - 1, depth, fromDto, toDto, path, explored, null);
            }

            String reason = "No call path from " + fromDto.name() + " to " + toDto.name()
                + " within " + depth + " hop(s) (" + explored + " function(s) explored)";
            if (truncated) {
                reason += "; the search stopped at the cap of " + MAX_CALL_PATH_NODES
                    + " visited function(s), so a path beyond it was not looked for";
            }
            return new CallPathDto(false, 0, depth, fromDto, toDto, List.of(), explored, reason);
        });
    }

    /**
     * Resolve a function from an address or a name.
     *
     * <p>An address inside a function body resolves to the function that
     * holds it, so the caller does not have to know the entry point.
     */
    private Function resolveFunction(Program program, String ref) {
        if (ref == null || ref.isBlank()) {
            throw new IllegalArgumentException("A function address or name is required");
        }
        String key = ref.trim();

        Function fn = functionService.findByAddress(program, key);
        if (fn == null) {
            fn = functionService.findContaining(program, key);
        }
        if (fn == null) {
            fn = functionService.findByName(program, key);
        }
        if (fn == null) {
            throw new NotFoundException("No function at address or named '" + key + "'", "FUNCTION_NOT_FOUND");
        }
        return fn;
    }

    /** The entry points of the functions the given function calls. */
    private Set<String> calleeAddresses(Program program, Function fn) {
        Set<String> addresses = new LinkedHashSet<>();
        for (XrefDto xref : xrefService.getCallsFromFunction(program, fn)) {
            String calleeAddr = xref.toFunctionAddress();
            if (calleeAddr != null) {
                addresses.add(calleeAddr);
            }
        }
        return addresses;
    }

    /**
     * Rebuild the path from the parent map the search filled in.
     *
     * <p>The chain is walked from the last hop back to the source, and the
     * cursor itself belongs to it: the function that made the call is a link
     * of the path, not a detail of the search. The source is the head of that
     * chain, so it is added once - adding it again would put it twice and
     * leave out the function in between.
     */
    private List<FunctionSummaryDto> buildPath(Program program, Map<String, String> parent,
            String lastHop, FunctionSummaryDto fromDto, FunctionSummaryDto toDto) {
        List<String> chain = new ArrayList<>();
        String cursor = lastHop;
        int guard = 0;
        while (guard++ < 1024) {
            chain.add(0, cursor);
            String previous = parent.get(cursor);
            if (previous == null) {
                break;
            }
            cursor = previous;
        }

        List<FunctionSummaryDto> path = new ArrayList<>();
        for (int i = 0; i < chain.size(); i++) {
            String address = chain.get(i);
            if (i == 0 && address.equals(fromDto.address())) {
                path.add(fromDto);
                continue;
            }
            Function fn = functionService.findByAddress(program, address);
            if (fn != null) {
                path.add(FunctionSummaryDto.from(fn));
            }
        }
        path.add(toDto);
        return path;
    }

    /** A function in the search queue, with the depth it was reached at. */
    private record CallPathNode(Function function, String address, int depth) {
    }

    private List<Map<String, Object>> buildCallTree(Program program, Function fn, int depth, boolean callers, Set<String> visited) {
        if (depth <= 0) {
            return Collections.emptyList();
        }

        List<Map<String, Object>> result = new ArrayList<>();
        String addr = fn.getEntryPoint().toString();

        // Callers: refs TO the entry address. Callees: CALL refs from anywhere
        // inside the body (the entry address itself almost never makes a call).
        List<XrefDto> xrefs = callers
            ? xrefService.getCallsTo(program, addr)
            : xrefService.getCallsFromFunction(program, fn);

        for (XrefDto xref : xrefs) {
            String targetAddr = callers ? xref.fromFunctionAddress() : xref.toFunctionAddress();
            if (targetAddr == null || visited.contains(targetAddr)) {
                continue;
            }

            Function targetFn = functionService.findByAddress(program, targetAddr);
            if (targetFn == null) {
                continue;
            }

            visited.add(targetAddr);

            Map<String, Object> node = new LinkedHashMap<>();
            node.put("function", FunctionSummaryDto.from(targetFn));

            if (depth > 1) {
                List<Map<String, Object>> children = buildCallTree(program, targetFn, depth - 1, callers, visited);
                if (!children.isEmpty()) {
                    node.put(callers ? "callers" : "callees", children);
                }
            }

            result.add(node);
        }

        return result;
    }
}
