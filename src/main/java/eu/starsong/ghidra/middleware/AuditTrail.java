package eu.starsong.ghidra.middleware;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.javalin.Javalin;
import io.javalin.http.Context;

/**
 * A local JSONL record of every mutation (I12).
 *
 * <p>One line per state-changing request — when it happened, the request id
 * that the response envelope already carries, the method and path, the status,
 * how long it took and the instance port. The file is local only
 * ({@code ~/.ghydra/audit.jsonl} by default), capped at about 1 MB by dropping
 * the oldest lines, and disabled with {@code GHYDRA_AUDIT=0}.
 *
 * <p>What it deliberately does not record: the request body. A mutation's
 * payload can carry program data, paths and names; the digest of the response
 * plus the request id is enough to correlate a line with a log entry without
 * copying the analysis into a file that outlives it.
 */
public final class AuditTrail {

    /** Where the log lives; empty/unset means the default under the home directory. */
    public static final String ENV_PATH = "GHYDRA_AUDIT_LOG";

    /** Set to 0/false/off to disable the trail. */
    public static final String ENV_DISABLED = "GHYDRA_AUDIT";

    private static final long MAX_BYTES = 1_000_000L;
    private static final int KEEP_LINES = 2000;
    private static final Object LOCK = new Object();

    private AuditTrail() {
    }

    /** Is the trail on? It is on unless explicitly disabled. */
    public static boolean enabled() {
        String value = System.getenv(ENV_DISABLED);
        if (value == null || value.isBlank()) {
            return true;
        }
        String text = value.trim().toLowerCase(Locale.ROOT);
        return !(text.equals("0") || text.equals("false") || text.equals("off")
            || text.equals("no"));
    }

    /** The file the trail is appended to. */
    public static Path path() {
        String configured = System.getenv(ENV_PATH);
        if (configured != null && !configured.isBlank()) {
            return Paths.get(configured).toAbsolutePath();
        }
        String home = System.getProperty("user.home", ".");
        return Paths.get(home, ".ghydra", "audit.jsonl").toAbsolutePath();
    }

    /** Record a mutation, if the trail is on. Never throws into a request. */
    public static void record(String requestId, String method, String path,
            int status, long durationMs, int port) {
        if (!enabled()) {
            return;
        }
        String line = "{\"ts\":" + Instant.now().toEpochMilli()
            + ",\"request_id\":\"" + escape(requestId)
            + "\",\"method\":\"" + escape(method)
            + "\",\"path\":\"" + escape(path)
            + "\",\"status\":" + status
            + ",\"ms\":" + durationMs
            + ",\"port\":" + port + "}\n";
        try {
            synchronized (LOCK) {
                Path file = path();
                Path parent = file.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                trim(file);
                Files.write(file, line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
        } catch (IOException | RuntimeException ignored) {
            // The trail must never break the request it is recording.
        }
    }

    /** Keep the file bounded by dropping the oldest lines. */
    private static void trim(Path file) throws IOException {
        if (!Files.exists(file) || Files.size(file) <= MAX_BYTES) {
            return;
        }
        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        int from = Math.max(0, lines.size() - KEEP_LINES);
        Files.write(file,
            (String.join("\n", lines.subList(from, lines.size())) + "\n")
                .getBytes(StandardCharsets.UTF_8),
            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    /**
     * Record every mutation once its handler is done.
     *
     * <p>Registered as an {@code after} handler so the status and the duration
     * are the real ones, and after the read-only guard, so a refused mutation
     * is recorded as a 403 (which is the useful line: someone tried).
     */
    public static void register(Javalin app, int port) {
        if (!enabled()) {
            return;
        }
        app.before(ctx -> ctx.attribute("ghydra.audit.start", System.nanoTime()));
        app.after(ctx -> {
            if (!ReadOnlyGuard.isMutating(ctx.method().name())) {
                return;
            }
            Long started = ctx.attribute("ghydra.audit.start");
            long durationMs = started == null ? 0L
                : Math.max(0L, (System.nanoTime() - started) / 1_000_000L);
            String requestId = ctx.header("X-Request-ID");
            record(requestId == null ? "" : requestId, ctx.method().name(),
                ctx.path(), ctx.statusCode(), durationMs, port);
        });
    }

    /** JSON string escaping for the handful of fields a line carries. */
    static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}
