package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.DecompileResultDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.DecompilerCache;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;

import java.util.ArrayList;
import java.util.List;

/**
 * Service for decompilation operations.
 */
public class DecompilerService {

    private static final int DEFAULT_TIMEOUT = 60;

    private final FunctionService functionService;
    private final DecompilerCache cache = DecompilerCache.shared();

    public DecompilerService(FunctionService functionService) {
        this.functionService = functionService;
    }

    public DecompilerService() {
        this.functionService = new FunctionService();
    }

    /**
     * Decompile a function by its address.
     */
    public DecompileResultDto decompile(Program program, String addressStr) {
        return decompile(program, addressStr, DEFAULT_TIMEOUT);
    }

    /**
     * Decompile a function by its address with a custom timeout.
     */
    public DecompileResultDto decompile(Program program, String addressStr, int timeout) {
        Function function = functionService.findByAddress(program, addressStr);
        if (function == null) {
            throw new NotFoundException("Function not found at address: " + addressStr, "FUNCTION_NOT_FOUND");
        }

        return decompileFunction(program, function, timeout);
    }

    /**
     * Decompile a function by its name.
     */
    public DecompileResultDto decompileByName(Program program, String name) {
        return decompileByName(program, name, DEFAULT_TIMEOUT);
    }

    /**
     * Decompile a function by its name with a custom timeout.
     */
    public DecompileResultDto decompileByName(Program program, String name, int timeout) {
        Function function = functionService.findByName(program, name);
        if (function == null) {
            throw new NotFoundException("Function not found with name: " + name, "FUNCTION_NOT_FOUND");
        }

        return decompileFunction(program, function, timeout);
    }

    /**
     * Decompile a Ghidra Function.
     */
    public DecompileResultDto decompileFunction(Program program, Function function, int timeout) {
        String functionName = function.getName();
        String functionAddress = function.getEntryPoint().toString();

        DecompileResults results = cache.getDecompileResults(program, function, timeout);

        if (results == null || !results.decompileCompleted()) {
            String error = results != null ? results.getErrorMessage() : null;
            if (error == null || error.isEmpty()) {
                error = "Decompilation did not complete";
            }
            return DecompileResultDto.failure(functionName, functionAddress, error);
        }

        HighFunction highFunction = results.getHighFunction();
        if (highFunction == null) {
            return DecompileResultDto.failure(functionName, functionAddress, "No high-level function available");
        }

        String decompilation = results.getDecompiledFunction().getC();
        if (decompilation == null || decompilation.isEmpty()) {
            return DecompileResultDto.failure(functionName, functionAddress, "Empty decompilation result");
        }

        return DecompileResultDto.success(functionName, functionAddress, decompilation);
    }

    /**
     * Decompile a list of functions in one call.
     *
     * <p>A target is an address or a function name. A target that resolves to
     * nothing comes back as a failed entry instead of aborting the batch: a
     * triage pass wants to see which ones were wrong, not lose the other
     * nine.
     *
     * <p>Decompiler work stays off the EDT — one DecompInterface is shared
     * by the cache, and wrapping it would freeze the Ghidra UI for the whole
     * batch.
     */
    public List<DecompileResultDto> decompileBatch(Program program, List<String> targets, int timeout) {
        List<DecompileResultDto> results = new ArrayList<>();
        if (targets == null) {
            return results;
        }
        for (String target : targets) {
            if (target == null || target.isBlank()) {
                continue;
            }
            results.add(decompileTarget(program, target.trim(), timeout));
        }
        return results;
    }

    /**
     * Decompile one target of a batch, by address or by name.
     */
    private DecompileResultDto decompileTarget(Program program, String target, int timeout) {
        Function function = functionService.findByAddress(program, target);
        if (function == null) {
            function = functionService.findByName(program, target);
        }
        if (function == null) {
            return DecompileResultDto.failure(target, null,
                "No function at that address or with that name");
        }
        return decompileFunction(program, function, timeout);
    }

    /**
     * Get the high-level function (P-Code) for a function.
     * This is useful for more advanced analysis.
     */
    public HighFunction getHighFunction(Program program, Function function, int timeout) {
        DecompileResults results = cache.getDecompileResults(program, function, timeout);
        return (results != null && results.decompileCompleted()) ? results.getHighFunction() : null;
    }

    /** Release the cached decompiler. Call on shutdown. */
    public void dispose() {
        cache.dispose();
    }
}
