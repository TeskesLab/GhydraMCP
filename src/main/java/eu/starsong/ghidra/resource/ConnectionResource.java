package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import io.javalin.Javalin;
import io.javalin.http.Context;
import java.util.function.Function;

/** Read-only catalog: no provisioning, credentials, endpoints, or credential references. */
public final class ConnectionResource implements Resource {
    @Override public void register(Javalin app, Function<Context, GhidraContext> factory) {
        app.get("/connections", request -> {
            GhidraContext context = factory.apply(request);
            var profiles = ConnectionProfiles.list();
            var response = Response.ok(request, context.port(), profiles)
                .self("/connections").link("instances", "/instances");
            for (var profile : profiles) {
                String id = String.valueOf(profile.get("id"));
                String route = "bsim".equals(profile.get("kind")) ? "/bsim/status" : "/repositories";
                response.link("profile_" + id, route + "?profile="
                    + java.net.URLEncoder.encode(id, java.nio.charset.StandardCharsets.UTF_8));
            }
            context.json(response.build());
        });
    }
}
