package eu.starsong.ghidra.middleware;

import java.util.Locale;

import eu.starsong.ghidra.hateoas.Response;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;

/**
 * A read-only instance refuses every mutation (I12).
 *
 * <p>Enabled with {@code -Dghidra.mcp.readOnly=true} or {@code GHYDRA_READ_ONLY=1}.
 * The check is one {@code before} handler instead of a flag in every service,
 * so a mutation endpoint added later is covered without anyone remembering to
 * ask: {@code POST}, {@code PUT}, {@code PATCH} and {@code DELETE} are refused
 * with a {@code 403 READ_ONLY_MODE}, while every read path is untouched.
 *
 * <p>This is the "no prompts" security mode the roadmap asked for: an agent
 * can be pointed at a production analysis with the guarantee that it cannot
 * modify it, and the refusal names the switch that would lift it.
 */
public final class ReadOnlyGuard {

    /** System property that turns the mode on. */
    public static final String PROPERTY = "ghidra.mcp.readOnly";

    /** Environment variable that turns the mode on. */
    public static final String ENV = "GHYDRA_READ_ONLY";

    /** The error code a refused mutation carries. */
    public static final String CODE = "READ_ONLY_MODE";

    private ReadOnlyGuard() {
    }

    /** Is read-only mode on? The property wins, the environment is the fallback. */
    public static boolean enabled() {
        String property = System.getProperty(PROPERTY);
        if (property != null && !property.isBlank()) {
            return truthy(property);
        }
        return truthy(System.getenv(ENV));
    }

    /** The HTTP methods that change state; everything else is a read. */
    public static boolean isMutating(String method) {
        if (method == null) {
            return false;
        }
        switch (method.toUpperCase(Locale.ROOT)) {
            case "POST":
            case "PUT":
            case "PATCH":
            case "DELETE":
                return true;
            default:
                return false;
        }
    }

    /**
     * Refuse every mutation when the mode is on.
     *
     * <p>Call this after the CORS handler (so a pre-flight is answered with its
     * headers) and before the resources are registered.
     */
    public static void register(Javalin app, int port) {
        if (!enabled()) {
            return;
        }
        app.before(ctx -> {
            if (!isMutating(ctx.method().name())) {
                return;
            }
            refuse(ctx, port);
        });
    }

    /** Write the refusal and stop: the endpoint never runs. */
    static void refuse(Context ctx, int port) {
        ctx.status(HttpStatus.FORBIDDEN);
        ctx.json(Response.error(ctx, port, "READ_ONLY_MODE",
            "this instance runs in read-only mode, so " + ctx.method().name()
                + " " + ctx.path() + " is refused. Restart Ghidra without "
                + "-D" + PROPERTY + "=true / " + ENV + "=1 to allow mutations.")
            .build());
        ctx.skipRemainingHandlers();
    }

    static boolean truthy(String value) {
        if (value == null) {
            return false;
        }
        String text = value.trim().toLowerCase(Locale.ROOT);
        return text.equals("1") || text.equals("true") || text.equals("yes")
            || text.equals("on");
    }
}
