package eu.starsong.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import eu.starsong.ghidra.util.HttpUtil;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import generic.jar.ResourceFile;
import ghidra.util.task.TaskMonitor;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class ScriptEndpoints extends AbstractEndpoint {

    private final PluginTool tool;
    private volatile Boolean pyghidraAvailable = null;
    private final ConcurrentMap<String, Object> scriptLocks = new ConcurrentHashMap<>();

    public ScriptEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }

    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/script/execute", HttpUtil.safeHandler(this::handleScriptExecute, port));
        server.createContext("/script/capabilities", HttpUtil.safeHandler(this::handleScriptCapabilities, port));
    }

    @Override
    protected boolean requiresProgram() {
        return false;
    }

    private void handleScriptExecute(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            return;
        }

        Map<String, String> params = parseJsonPostParams(exchange);
        String code = params.get("code");
        String language = params.get("language");
        if (language == null || language.isEmpty()) {
            language = "python3";
        }

        if (code == null || code.isEmpty()) {
            sendErrorResponse(exchange, 400, "Missing 'code' parameter", "MISSING_CODE");
            return;
        }

        Program currentProgram = getCurrentProgram();

        if ("python3".equals(language) || "pyghidra".equals(language)) {
            handlePyGhidraScript(exchange, code, currentProgram);
        } else {
            sendErrorResponse(exchange, 400,
                "Unsupported language: " + language + ". Only 'python3' is supported.",
                "UNSUPPORTED_LANGUAGE");
        }
    }

    private void handlePyGhidraScript(HttpExchange exchange, String code, Program currentProgram)
            throws IOException {
        if (!isPyGhidraAvailable()) {
            sendErrorResponse(exchange, 503,
                "PyGhidra (Python 3) runtime is not available. " +
                "Ghidra must be launched via 'pyghidraRun' to enable Python 3 script execution.",
                "PYGHIDRA_NOT_AVAILABLE");
            return;
        }

        GhidraScriptProvider provider = getPyGhidraProvider();
        if (provider == null) {
            sendErrorResponse(exchange, 503,
                "PyGhidraScriptProvider not found",
                "PYGHIDRA_PROVIDER_NOT_FOUND");
            return;
        }

        Path tempScript = null;
        try {
            tempScript = Files.createTempFile("ghydra_script_", ".py");
            Files.writeString(tempScript, code, StandardCharsets.UTF_8);
            ResourceFile scriptFile = new ResourceFile(tempScript.toFile());

            String lockKey = "script_" + Thread.currentThread().threadId();
            scriptLocks.put(lockKey, lockKey);
            try {
                executeScriptInGhidra(exchange, provider, scriptFile, currentProgram);
            } finally {
                scriptLocks.remove(lockKey);
            }
        } catch (Exception e) {
            Msg.error(this, "Error executing PyGhidra script", e);
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));

            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(false)
                .result(Map.of(
                    "stdout", "",
                    "stderr", sw.toString(),
                    "exitCode", -1
                ))
                .addLink("self", "/script/execute")
                .addLink("capabilities", "/script/capabilities");
            sendJsonResponse(exchange, builder.build(), 500);
        } finally {
            if (tempScript != null) {
                try { Files.deleteIfExists(tempScript); } catch (IOException ignored) {}
            }
        }
    }

    private void executeScriptInGhidra(HttpExchange exchange, GhidraScriptProvider provider,
            ResourceFile scriptFile, Program currentProgram) throws IOException {
        StringWriter stdoutWriter = new StringWriter();
        StringWriter stderrWriter = new StringWriter();
        PrintWriter stdout = new PrintWriter(stdoutWriter);
        PrintWriter stderr = new PrintWriter(stderrWriter);

        GhidraState state = new GhidraState(tool, null, currentProgram, null, null, null);
        TaskMonitor monitor = new ghidra.util.task.ConsoleTaskMonitor();
        ScriptControls controls = new ScriptControls(stdout, stderr, monitor);

        try {
            GhidraScript script = provider.getScriptInstance(scriptFile, stderr);
            if (script == null) {
                sendErrorResponse(exchange, 500,
                    "Failed to instantiate PyGhidra script. Python interpreter may not be properly initialized.",
                    "SCRIPT_INSTANTIATION_FAILED");
                return;
            }

            Msg.info(this, "Executing PyGhidra script via script_execute endpoint");
            script.execute(state, controls);

            String stdoutStr = stdoutWriter.toString().trim();
            String stderrStr = stderrWriter.toString().trim();

            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(true)
                .result(Map.of(
                    "stdout", stdoutStr,
                    "stderr", stderrStr,
                    "exitCode", 0,
                    "language", "python3"
                ))
                .addLink("self", "/script/execute")
                .addLink("capabilities", "/script/capabilities");
            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "PyGhidra script execution failed", e);

            StringWriter errorStack = new StringWriter();
            e.printStackTrace(new PrintWriter(errorStack));

            String stderrStr = stderrWriter.toString().trim();
            if (!stderrStr.isEmpty()) {
                stderrStr += "\n" + errorStack.toString();
            } else {
                stderrStr = errorStack.toString();
            }

            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(false)
                .result(Map.of(
                    "stdout", stdoutWriter.toString().trim(),
                    "stderr", stderrStr.trim(),
                    "exitCode", 1,
                    "error", e.getClass().getSimpleName() + ": " + e.getMessage()
                ))
                .addLink("self", "/script/execute")
                .addLink("capabilities", "/script/capabilities");
            sendJsonResponse(exchange, builder.build(), 200);
        }
    }

    private void handleScriptCapabilities(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            return;
        }

        boolean pyghidra = isPyGhidraAvailable();

        Map<String, Object> capabilities = new HashMap<>();
        capabilities.put("python3", pyghidra);
        capabilities.put("jython", true);
        capabilities.put("pyghidra_available", pyghidra);

        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(true)
            .result(capabilities)
            .addLink("self", "/script/capabilities")
            .addLink("execute", "/script/execute", "POST");
        sendJsonResponse(exchange, builder.build(), 200);
    }

    public boolean isPyGhidraAvailable() {
        if (pyghidraAvailable != null) {
            return pyghidraAvailable;
        }

        try {
            GhidraScriptProvider provider = getPyGhidraProvider();
            if (provider == null) {
                pyghidraAvailable = false;
                return false;
            }

            Path tempFile = null;
            try {
                tempFile = Files.createTempFile("pyghidra_test_", ".py");
                Files.writeString(tempFile, "# PyGhidra availability test\n", StandardCharsets.UTF_8);
                ResourceFile rf = new ResourceFile(tempFile.toFile());
                GhidraScript instance = provider.getScriptInstance(rf, null);
                pyghidraAvailable = (instance != null);
            } finally {
                if (tempFile != null) {
                    try { Files.deleteIfExists(tempFile); } catch (IOException ignored) {}
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "PyGhidra availability check failed: " + e.getMessage());
            pyghidraAvailable = false;
        }

        Msg.info(this, "PyGhidra availability: " + pyghidraAvailable);
        return pyghidraAvailable;
    }

    private GhidraScriptProvider getPyGhidraProvider() {
        try {
            for (GhidraScriptProvider provider : GhidraScriptUtil.getProviders()) {
                String runtimeName = provider.getRuntimeEnvironmentName();
                if ("PyGhidra".equals(runtimeName)) {
                    return provider;
                }
            }
            Msg.debug(this, "No provider with runtimeEnvironmentName 'PyGhidra' found. " +
                "Available runtimes: " + GhidraScriptUtil.getProviders().stream()
                    .map(p -> p.getRuntimeEnvironmentName() + "(" + p.getClass().getSimpleName() + ")")
                    .reduce((a, b) -> a + ", " + b).orElse("none"));
            return null;
        } catch (Exception e) {
            Msg.debug(this, "Failed to enumerate script providers: " + e.getMessage());
            return null;
        }
    }
}
