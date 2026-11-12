package eu.starsong.ghidra.server;

import eu.starsong.ghidra.api.ApiConstants;
import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.middleware.AuditTrail;
import eu.starsong.ghidra.middleware.CorsHandler;
import eu.starsong.ghidra.middleware.ReadOnlyGuard;
import eu.starsong.ghidra.middleware.ErrorHandler;
import eu.starsong.ghidra.service.CompatibilityService;
import eu.starsong.ghidra.util.IncompatibleGhidraBuildException;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.javalin.Javalin;
import io.javalin.http.HttpStatus;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Factory and manager for the Javalin HTTP server.
 * Handles server creation, configuration, and lifecycle.
 */
public class GhydraServer {

    private final PluginTool tool;
    private final int port;
    private final Map<Integer, Object> activeInstances;
    private final boolean isBaseInstance;
    private final List<Resource> resources = new ArrayList<>();

    /** Shared headless selection and its extra program consumer. */
    private final ActiveProgram activeProgram;

    private Javalin app;
    private final Object lifecycle = new Object();
    private int activeRequests;
    private boolean stopping;

    public GhydraServer(PluginTool tool, int port, Map<Integer, Object> activeInstances, boolean isBaseInstance) {
        this(tool, port, activeInstances, isBaseInstance, null, null);
    }

    /**
     * A server for an instance that runs without a CodeBrowser.
     *
     * <p>Headless there is no PluginTool to ask for the current program, so the
     * program and the project are handed over instead: the ones the headless
     * run imported and opened.
     */
    public GhydraServer(PluginTool tool, int port, Map<Integer, Object> activeInstances, boolean isBaseInstance,
            ghidra.program.model.listing.Program program, ghidra.framework.model.Project project) {
        this.tool = tool;
        this.port = port;
        this.activeInstances = activeInstances;
        this.isBaseInstance = isBaseInstance;
        this.activeProgram = new ActiveProgram(program, project);
    }

    /**
     * Register a resource with the server.
     */
    public GhydraServer register(Resource resource) {
        resources.add(resource);
        return this;
    }

    /**
     * Register multiple resources with the server.
     */
    public GhydraServer register(Resource... resources) {
        for (Resource r : resources) {
            this.resources.add(r);
        }
        return this;
    }

    /**
     * Start the server.
     */
    public void start() {
        eu.starsong.ghidra.connection.WorkerTLS.initialize();
        app = Javalin.create(config -> {
            config.showJavalinBanner = false;

            config.router.contextPath = "/";

            config.jsonMapper(new GsonMapper());
        });

        configureMiddleware();

        registerResources();

        // Detect the running Ghidra series and the signatures of the APIs that
        // moved between 11.x and 12.2, before any request can hit them.
        CompatibilityService.logAtStartup();

        // Credential workers stay local unless the operator explicitly selects an interface.
        // Ordinary instances retain their historical cross-host default.
        String bindHost = System.getProperty("ghidra.mcp.bind.host");
        if (bindHost == null || bindHost.isEmpty()) {
            bindHost = System.getenv("GHYDRA_BIND_HOST");
        }
        if ((bindHost == null || bindHost.isEmpty()) && ConnectionProfiles.enabled()) {
            bindHost = "127.0.0.1";
        }
        if (bindHost != null && !bindHost.isEmpty()) {
            app.start(bindHost, port);
            Msg.info(this, "GhydraMCP HTTP server started on " + bindHost + ":" + port);
        } else {
            app.start(port);
            Msg.info(this, "GhydraMCP HTTP server started on port " + port);
        }
    }

    /**
     * Stop the server.
     */
    public void stop() {
        if (stopChecked(() -> {})) Thread.currentThread().interrupt();
    }

    boolean isHeadless() { return tool == null; }

    boolean stopChecked(Runnable preflight) {
        boolean interrupted = false;
        synchronized (lifecycle) {
            stopping = true;
            long deadline = isHeadless()
                ? System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5) : Long.MAX_VALUE;
            while (activeRequests != 0) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    stopping = false;
                    throw new eu.starsong.ghidra.connection.ConnectionException(
                        "REPOSITORY_CONFLICT", 409, "Worker requests are still active; shutdown was refused.");
                }
                try {
                    java.util.concurrent.TimeUnit.NANOSECONDS.timedWait(lifecycle, remaining);
                } catch (InterruptedException cancelled) {
                    if (isHeadless()) {
                        stopping = false;
                        Thread.currentThread().interrupt();
                        throw new eu.starsong.ghidra.connection.ConnectionException(
                            "REPOSITORY_CONFLICT", 409, "Worker shutdown was interrupted.");
                    }
                    interrupted = true; // GUI disposal must retain ownership until cleanup completes.
                }
            }
        }
        try {
            preflight.run();
            if (app != null) {
                app.stop();
                Msg.info(this, "GhydraMCP HTTP server stopped on port " + port);
            }
        } finally {
            synchronized (lifecycle) { stopping = false; }
        }
        return interrupted;
    }

    /**
     * Get the Javalin app instance.
     */
    public Javalin app() {
        return app;
    }

    /**
     * Get the server port.
     */
    public int port() {
        return port;
    }

    /**
     * Check if this is the base instance.
     */
    public boolean isBaseInstance() {
        return isBaseInstance;
    }

    // -------------------------------------------------------------------------
    // Private methods
    // -------------------------------------------------------------------------

    private void configureMiddleware() {
        app.before(new CorsHandler());
        app.before(ctx -> {
            synchronized (lifecycle) {
                if (!stopping) {
                    activeRequests++;
                    ctx.attribute("ghydra.request-active", true);
                    return;
                }
            }
            ctx.status(503);
            ctx.json(Response.error(ctx, port, "WORKER_STOPPING", "The worker is checking shutdown safety.").build());
            ctx.skipRemainingHandlers();
        });
        app.after(ctx -> {
            synchronized (lifecycle) {
                if (Boolean.TRUE.equals(ctx.attribute("ghydra.request-active"))) {
                    ctx.attribute("ghydra.request-active", false);
                    activeRequests--;
                    lifecycle.notifyAll();
                }
            }
        });

        // I12: a read-only instance refuses every mutation, and every mutation
        // is written to a local audit trail. Registration order matters: CORS
        // answers the pre-flight, the guard refuses, the trail records.
        ReadOnlyGuard.register(app, port);
        AuditTrail.register(app, port);


        app.exception(eu.starsong.ghidra.connection.ConnectionException.class, (e, ctx) -> {
            ctx.status(e.status());
            ctx.json(Response.error(ctx, port, e.code(), e.getMessage()).build());
        });
        app.exception(eu.starsong.ghidra.service.RepositoryService.RepositoryException.class, (e, ctx) -> {
            ctx.status(e.status());
            ctx.json(Response.error(ctx, port, e.code(), e.getMessage()).build());
        });
        app.exception(GhidraContext.NoProgramException.class, (e, ctx) -> {
            ctx.status(HttpStatus.SERVICE_UNAVAILABLE);
            ctx.json(Response.error(ctx, port, "NO_PROGRAM_LOADED", e.getMessage()).build());
        });

        app.exception(eu.starsong.ghidra.service.ProjectService.NoProjectException.class, (e, ctx) -> {
            ctx.status(HttpStatus.SERVICE_UNAVAILABLE);
            ctx.json(Response.error(ctx, port, "NO_PROJECT_OPEN", e.getMessage()).build());
        });

        app.exception(NotFoundException.class, (e, ctx) -> {
            ctx.status(HttpStatus.NOT_FOUND);
            ctx.json(Response.error(ctx, port, e.errorCode(), e.getMessage()).build());
        });

        // An endpoint that needs a CodeBrowser, on an instance that has none.
        // That is the server's limitation, not a mistake in the request.
        app.exception(HeadlessException.class, (e, ctx) -> {
            ctx.status(HttpStatus.SERVICE_UNAVAILABLE);
            ctx.json(Response.error(ctx, port, "HEADLESS_LIMITATION", e.getMessage()).build());
        });

        app.exception(BadRequestException.class, (e, ctx) -> {
            ctx.status(HttpStatus.BAD_REQUEST);
            ctx.json(Response.error(ctx, port, e.errorCode(), e.getMessage()).build());
        });

        // A write that couldn't be committed — almost always a read-only/locked program.
        // That's a conflict with the program's current state, not a server fault, so 409
        // rather than letting it fall through to the 500 handler below.
        app.exception(TransactionHelper.TransactionException.class, (e, ctx) -> {
            ctx.status(HttpStatus.CONFLICT);
            ctx.json(Response.error(ctx, port, "TRANSACTION_FAILED", e.getMessage()).build());
        });

        // Validation failures conventionally surface as IllegalArgumentException
        // (bad address, malformed param, etc.); treat them as 400, not 500.
        app.exception(IllegalArgumentException.class, (e, ctx) -> {
            ctx.status(HttpStatus.BAD_REQUEST);
            ctx.json(Response.error(ctx, port, "BAD_REQUEST",
                eu.starsong.ghidra.connection.ConnectionProfiles.enabled()
                    ? "Invalid request parameters." : e.getMessage()).build());
        });

        // Malformed request bodies (bodyAsClass) throw from Gson; that's client error, not 500.
        app.exception(com.google.gson.JsonSyntaxException.class, (e, ctx) -> {
            ctx.status(HttpStatus.BAD_REQUEST);
            ctx.json(Response.error(ctx, port, "INVALID_JSON",
                eu.starsong.ghidra.connection.ConnectionProfiles.enabled()
                    ? "Malformed JSON request." : "Malformed JSON body: " + e.getMessage()).build());
        });

        // A jar built against the wrong Ghidra series throws NoSuchMethodError —
        // an Error, which Javalin cannot register a handler for (its exception()
        // API is bounded by Exception). TransactionHelper converts it to this
        // unchecked exception so the answer is a structured 500 with a body and
        // a remedy, instead of an empty 500 with nothing in the log.
        app.exception(IncompatibleGhidraBuildException.class, (e, ctx) -> {
            Msg.error(this, "Incompatible Ghidra build at " + ctx.path(), e);
            ctx.status(HttpStatus.INTERNAL_SERVER_ERROR);
            ctx.json(Response.error(ctx, port, "INCOMPATIBLE_GHIDRA_BUILD",
                e.getMessage() + " Rebuild the extension with GHIDRA_HOME pointing at the "
                + "installed Ghidra and -Dghidra.version=<that series>, so the deployed jar "
                + "matches the API it is loaded into.").build());
        });

        app.exception(Exception.class, new ErrorHandler(port));
    }

    private void registerResources() {
        for (Resource resource : resources) {
            resource.register(app, this::createContext);
        }
    }

    /**
     * Create a GhidraContext from a Javalin Context.
     * This is passed to resources for creating handlers.
     */
    private GhidraContext createContext(io.javalin.http.Context ctx) {
        return new GhidraContext(ctx, tool, port, activeInstances, activeProgram);
    }

    void releaseActiveProgram() {
        activeProgram.close();
    }

    // -------------------------------------------------------------------------
    // Static utility methods
    // -------------------------------------------------------------------------

    /**
     * Find an available port starting from the default port.
     */
    public static int findAvailablePort(Map<Integer, ?> activeInstances) {
        int basePort = ApiConstants.DEFAULT_PORT;
        int maxAttempts = ApiConstants.MAX_PORT_ATTEMPTS;

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            int candidate = basePort + attempt;
            if (!activeInstances.containsKey(candidate)) {
                try (ServerSocket s = new ServerSocket(candidate)) {
                    return candidate;
                } catch (IOException e) {
                    // Port not available, try next
                }
            }
        }

        throw new RuntimeException("Could not find available port after " + maxAttempts + " attempts");
    }

    // -------------------------------------------------------------------------
    // Exception classes
    // -------------------------------------------------------------------------

    public static class NotFoundException extends RuntimeException {
        private final String errorCode;

        public NotFoundException(String message) {
            this(message, "NOT_FOUND");
        }

        public NotFoundException(String message, String errorCode) {
            super(message);
            this.errorCode = errorCode;
        }

        public String errorCode() {
            return errorCode;
        }
    }

    public static class BadRequestException extends RuntimeException {
        private final String errorCode;

        public BadRequestException(String message) {
            this(message, "BAD_REQUEST");
        }

        public BadRequestException(String message, String errorCode) {
            super(message);
            this.errorCode = errorCode;
        }

        public String errorCode() {
            return errorCode;
        }
    }

    /**
     * An endpoint that needs a CodeBrowser, on an instance that runs headless.
     *
     * <p>The UI endpoints report where the human's cursor is, and opening a
     * project file needs a window to open it in. Neither exists without a
     * CodeBrowser, and saying so is better than failing with a
     * NullPointerException.
     */
    public static class HeadlessException extends RuntimeException {
        public HeadlessException(String message) {
            super(message);
        }
    }
}
