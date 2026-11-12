package eu.starsong.ghidra.server;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.javalin.http.Context;

import java.util.Map;
import java.util.Optional;

/**
 * Extended context for Javalin requests that provides access to Ghidra resources.
 * This class wraps a Javalin Context and adds Ghidra-specific functionality.
 */
public class GhidraContext {

    private final Context ctx;
    private final PluginTool tool;
    private final int port;
    private final Map<Integer, ?> activeInstances;

    /** Shared per-server headless selection; GUI selection stays with ProgramManager. */
    private final ActiveProgram activeProgram;

    public GhidraContext(Context ctx, PluginTool tool, int port, Map<Integer, ?> activeInstances) {
        this(ctx, tool, port, activeInstances, null, null);
    }

    public GhidraContext(Context ctx, PluginTool tool, int port, Map<Integer, ?> activeInstances,
            Program program, Project project) {
        this(ctx, tool, port, activeInstances, new ActiveProgram(program, project));
    }

    GhidraContext(Context ctx, PluginTool tool, int port, Map<Integer, ?> activeInstances,
            ActiveProgram activeProgram) {
        this.ctx = ctx;
        this.tool = tool;
        this.port = port;
        this.activeInstances = activeInstances;
        this.activeProgram = activeProgram;
    }

    // -------------------------------------------------------------------------
    // Javalin Context delegation
    // -------------------------------------------------------------------------

    /**
     * Get the underlying Javalin context.
     */
    public Context ctx() {
        return ctx;
    }

    /**
     * Get a path parameter by name.
     */
    public String pathParam(String name) {
        return ctx.pathParam(name);
    }

    /**
     * Get a query parameter by name.
     */
    public String queryParam(String name) {
        return ctx.queryParam(name);
    }

    /**
     * Get a query parameter with a default value.
     */
    public String queryParam(String name, String defaultValue) {
        String value = ctx.queryParam(name);
        return value != null ? value : defaultValue;
    }

    /**
     * Get a query parameter as an integer with a default value.
     */
    public int queryParamAsInt(String name, int defaultValue) {
        String value = ctx.queryParam(name);
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Get the request method.
     */
    public String method() {
        return ctx.method().name();
    }

    /**
     * Get the request path.
     */
    public String path() {
        return ctx.path();
    }

    /**
     * Parse the request body as JSON into the specified class.
     */
    public <T> T bodyAsClass(Class<T> clazz) {
        return ctx.bodyAsClass(clazz);
    }

    /**
     * Set the response status code.
     */
    public GhidraContext status(int code) {
        ctx.status(code);
        return this;
    }

    /**
     * Send a JSON response.
     */
    public void json(Object obj) {
        ctx.json(obj);
    }

    /**
     * Get pagination parameters from the request.
     */
    public Pagination pagination() {
        int offset = queryParamAsInt("offset", 0);
        int limit = queryParamAsInt("limit", 100);
        return new Pagination(offset, limit, countRequested());
    }

    /**
     * Does the client want the total?
     *
     * <p>A listing of a large binary pays for a walk over every entity to
     * count page matches. {@code ?count=false} says the caller only wants the
     * page: the walk is skipped, {@code meta.total} is absent and
     * {@code meta.counted} is false, so the client knows the number was not
     * computed rather than reading a wrong one.
     */
    private boolean countRequested() {
        String raw = queryParam("count");
        if (raw == null || raw.isBlank()) {
            return true;
        }
        String text = raw.trim().toLowerCase(java.util.Locale.ROOT);
        return !(text.equals("false") || text.equals("0") || text.equals("no"));
    }

    // -------------------------------------------------------------------------
    // Ghidra-specific methods
    // -------------------------------------------------------------------------

    /**
     * Get the Ghidra PluginTool.
     *
     * <p>Null in a headless instance: there is no CodeBrowser behind it, and
     * the handlers that need one answer that they cannot run instead of
     * failing with a NullPointerException.
     */
    public PluginTool tool() {
        return tool;
    }

    /**
     * Whether this instance runs without a CodeBrowser.
     *
     * <p>The UI endpoints need one, and so do the endpoints that open a file
     * in a new window.
     */
    public boolean isHeadless() {
        return tool == null;
    }

    /**
     * Get the server port.
     */
    public int port() {
        return port;
    }

    /**
     * Get the active instances map.
     */
    public Map<Integer, ?> activeInstances() {
        return activeInstances;
    }

    /**
     * Get the current program. Returns null if no program is loaded.
     */
    public Program program() {
        if (tool == null) {
            return activeProgram.program();
        }
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return null;
        }
        return pm.getCurrentProgram();
    }

    /**
     * Get the current program, throwing if none is loaded.
     * This should only be called from handlers that require a program.
     */
    public Program requireProgram() {
        Program p = program();
        if (p == null) {
            throw new NoProgramException("No program is currently loaded");
        }
        return p;
    }

    /**
     * Get the current program as an Optional.
     */
    public Optional<Program> programOptional() {
        return Optional.ofNullable(program());
    }

    /**
     * Get the current project.
     */
    public Project project() {
        if (tool == null) {
            return activeProgram.project();
        }
        return tool.getProject();
    }

    public boolean hasRepositorySelection() {
        return tool == null && activeProgram.hasSelection();
    }

    /** Activate an already-open repository program without discarding unsaved work. */
    public void activateProgram(Program program, Project project) {
        eu.starsong.ghidra.util.GhidraSwing.runRead(() -> {
            if (tool == null) {
                activeProgram.activate(program, project);
                return null;
            }
            ProgramManager manager = tool.getService(ProgramManager.class);
            if (manager == null) throw new IllegalStateException("ProgramManager is not available");
            Program current = manager.getCurrentProgram();
            if (current != null && current != program && current.isChanged()) {
                throw new eu.starsong.ghidra.connection.ConnectionException(
                    "REPOSITORY_CONFLICT", 409, "Save the active program before opening another program.");
            }
            manager.openProgram(program);
            manager.setCurrentProgram(program);
            return null;
        });
    }

    /**
     * Get the current project as an Optional.
     */
    public Optional<Project> projectOptional() {
        return Optional.ofNullable(project());
    }

    /**
     * Get the instance URL for HATEOAS links.
     */
    public String instanceUrl() {
        return "http://localhost:" + port;
    }

    // -------------------------------------------------------------------------
    // Pagination helper class
    // -------------------------------------------------------------------------

    public record Pagination(int offset, int limit, boolean counted) {
        public Pagination {
            if (offset < 0) offset = 0;
            if (limit < 1) limit = 100;
            if (limit > 1000) limit = 1000;
        }

        /** A counted page: the historical behaviour, and the default. */
        public Pagination(int offset, int limit) {
            this(offset, limit, true);
        }
    }

    // -------------------------------------------------------------------------
    // Exception for missing program
    // -------------------------------------------------------------------------

    public static class NoProgramException extends RuntimeException {
        public NoProgramException(String message) {
            super(message);
        }
    }
}
