package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.RepositoryService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/** Profile-only native Ghidra Server operations; no endpoint or authentication inputs. */
public final class RepositoryResource implements Resource {
    private final RepositoryService service;

    public RepositoryResource(RepositoryService service) { this.service = service; }

    @Override public void register(Javalin app, Function<Context, GhidraContext> factory) {
        app.get("/repositories", raw -> {
            rejectQuery(raw, Set.of("profile"));
            GhidraContext ctx = factory.apply(raw);
            respond(ctx, "/repositories", service.status(ctx.queryParam("profile")));
        });
        app.get("/repositories/files", raw -> {
            rejectQuery(raw, Set.of("profile", "path", "offset", "limit"));
            GhidraContext ctx = factory.apply(raw);
            String limit = ctx.queryParam("limit", "100");
            int bound;
            int offset;
            try {
                bound = Integer.parseInt(limit);
                offset = Integer.parseInt(ctx.queryParam("offset", "0"));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("offset and limit must be integers");
            }
            respond(ctx, "/repositories/files", service.files(ctx.queryParam("profile"),
                ctx.queryParam("path", "/"), offset, bound));
        });
        app.get("/repositories/inspect-match", raw -> {
            rejectQuery(raw, Set.of("profile", "match_id", "repository_url", "executable_md5",
                "address", "function", "version", "max_code_lines"));
            GhidraContext ctx = factory.apply(raw);
            Map<String, Object> match = new java.util.LinkedHashMap<>();
            for (String key : Set.of("match_id", "repository_url", "executable_md5", "address", "function")) {
                String value = ctx.queryParam(key);
                if (value != null) match.put(key, value);
            }
            int version;
            int maxCodeLines;
            try {
                version = Integer.parseInt(ctx.queryParam("version", "-1"));
                maxCodeLines = Integer.parseInt(ctx.queryParam("max_code_lines", "1000"));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("version and max_code_lines must be integers");
            }
            respond(ctx, "/repositories/inspect-match", service.inspectMatch(ctx.queryParam("profile"),
                match, version, maxCodeLines));
        });
        app.get("/repositories/export-match", raw -> {
            rejectQuery(raw, Set.of("profile", "match_id", "repository_url", "executable_md5",
                "address", "function", "version"));
            GhidraContext ctx = factory.apply(raw);
            Map<String, Object> match = new java.util.LinkedHashMap<>();
            for (String key : Set.of("match_id", "repository_url", "executable_md5", "address", "function")) {
                String value = ctx.queryParam(key);
                if (value != null) match.put(key, value);
            }
            int version;
            try { version = Integer.parseInt(ctx.queryParam("version", "-1")); }
            catch (NumberFormatException e) { throw new IllegalArgumentException("version must be an integer"); }
            respond(ctx, "/repositories/export-match", service.exportMatch(ctx.queryParam("profile"), match, version));
        });
        app.post("/repositories/open", raw -> {
            GhidraContext ctx = factory.apply(raw);
            Map<?, ?> body = body(ctx, Set.of("profile", "path", "version"));
            respond(ctx, "/repositories/open", service.open(ctx, text(body, "profile"),
                text(body, "path"), integer(body, "version", -1)));
        });
        app.post("/repositories/checkout", raw -> {
            GhidraContext ctx = factory.apply(raw);
            Map<?, ?> body = body(ctx, Set.of("profile", "path", "exclusive"));
            respond(ctx, "/repositories/checkout", service.checkout(text(body, "profile"),
                text(body, "path"), bool(body, "exclusive", false)));
        });
        app.post("/repositories/checkin", raw -> {
            GhidraContext ctx = factory.apply(raw);
            Map<?, ?> body = body(ctx, Set.of("profile", "path", "comment", "keep_checked_out"));
            respond(ctx, "/repositories/checkin", service.checkin(text(body, "profile"),
                text(body, "path"), text(body, "comment"), bool(body, "keep_checked_out", false)));
        });
    }

    private static void rejectQuery(Context ctx, Set<String> allowed) {
        if (!allowed.containsAll(ctx.queryParamMap().keySet())) {
            throw new IllegalArgumentException("Unsupported repository parameter");
        }
        for (var values : ctx.queryParamMap().values()) {
            if (values.size() != 1) throw new IllegalArgumentException("Duplicate repository parameter");
        }
    }

    private static Map<?, ?> body(GhidraContext ctx, Set<String> allowed) {
        rejectQuery(ctx.ctx(), Set.of());
        Map<?, ?> body = ctx.bodyAsClass(Map.class);
        if (body == null || !allowed.containsAll(body.keySet())) {
            throw new IllegalArgumentException("Unsupported repository field");
        }
        return body;
    }

    private static String text(Map<?, ?> body, String name) {
        Object value = body.get(name);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(name + " is required and must be a nonblank string");
        }
        return text;
    }

    private static boolean bool(Map<?, ?> body, String name, boolean fallback) {
        if (!body.containsKey(name)) return fallback;
        if (!(body.get(name) instanceof Boolean value)) throw new IllegalArgumentException(name + " must be boolean");
        return value;
    }

    private static int integer(Map<?, ?> body, String name, int fallback) {
        if (!body.containsKey(name)) return fallback;
        if (!(body.get(name) instanceof Number value) || !Double.isFinite(value.doubleValue())
                || value.doubleValue() != value.intValue()) throw new IllegalArgumentException(name + " must be an integer");
        return value.intValue();
    }

    private static void respond(GhidraContext ctx, String path, Object result) {
        var response = Response.ok(ctx.ctx(), ctx.port(), result).self(path)
            .link("connections", "/connections");
        if (result instanceof Map<?, ?> row && row.get("profile") instanceof String profile) {
            String query = "?profile=" + java.net.URLEncoder.encode(profile, java.nio.charset.StandardCharsets.UTF_8);
            response.link("repository", "/repositories" + query)
                .link("files", "/repositories/files" + query);
            if (Boolean.TRUE.equals(row.get("has_more"))) {
                String folder = java.net.URLEncoder.encode(String.valueOf(row.get("path")),
                    java.nio.charset.StandardCharsets.UTF_8);
                long next = ((Number) row.get("offset")).longValue() + ((Number) row.get("count")).longValue();
                response.link("next", "/repositories/files" + query + "&path=" + folder
                    + "&offset=" + next + "&limit=" + row.get("limit"));
            }
        }
        ctx.json(response.build());
    }
}
