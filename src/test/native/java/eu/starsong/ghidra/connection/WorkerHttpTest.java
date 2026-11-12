package eu.starsong.ghidra.connection;

import static org.junit.Assert.*;
import com.google.gson.JsonParser;
import eu.starsong.ghidra.resource.BSimResource;
import eu.starsong.ghidra.resource.ConnectionResource;
import eu.starsong.ghidra.resource.ScriptResource;
import eu.starsong.ghidra.server.GhydraServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Comparator;
import java.util.HashMap;
import org.junit.*;

/** Actual REST responses, not source-text assertions about error-handler implementation. */
public class WorkerHttpTest {
    private static final String SECRET = "SENTINEL_PRIVATE_WORKER_CREDENTIAL";
    private Path root;
    private GhydraServer server;
    private String oldDirectory;
    private String oldScripts;
    private String oldBind;
    private String base;
    private HttpClient client;

    @Before public void setup() throws Exception {
        oldDirectory = System.getProperty(ConnectionProfiles.PROPERTY);
        oldScripts = System.getProperty(ScriptResource.PROPERTY);
        oldBind = System.getProperty("ghidra.mcp.bind.host");
        root = Files.createTempDirectory("ghydra-http-worker-");
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
        file(".lock", "");
        file("profiles.json", "{\"version\":1,\"profiles\":{\"reader\":{\"kind\":\"bsim\","
            + "\"backend\":\"postgresql\",\"endpoint\":\"postgresql://private.invalid/corpus\","
            + "\"auth\":\"password\",\"credential_ref\":\"fixture\",\"permissions\":[\"query\"]}}}");
        file("credentials.json", "{\"version\":1,\"credentials\":{\"fixture\":{"
            + "\"username\":\"private-username\",\"password\":\"" + SECRET + "\"}}}");
        System.setProperty(ConnectionProfiles.PROPERTY, root.toString());
        System.setProperty(ScriptResource.PROPERTY, "true");
        System.setProperty("ghidra.mcp.bind.host", "127.0.0.1");
        server = new GhydraServer(null, 0, new HashMap<>(), false);
        server.register(new ConnectionResource(), new BSimResource(), new ScriptResource());
        server.start();
        server.app().get("/test/native-failure", request -> { throw new IllegalStateException(SECRET); });
        server.app().get("/test/invalid", request -> { throw new IllegalArgumentException(SECRET); });
        base = "http://127.0.0.1:" + server.app().port();
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    private void file(String name, String contents) throws Exception {
        Path path = root.resolve(name);
        Files.writeString(path, contents);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }

    private HttpResponse<String> request(String method, String path, String body) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(10))
            .header("Origin", "http://localhost").header("Content-Type", "application/json");
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofString(body));
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private void error(HttpResponse<String> response, int status, String code) {
        assertEquals(response.body(), status, response.statusCode());
        var envelope = JsonParser.parseString(response.body()).getAsJsonObject();
        assertFalse(envelope.get("success").getAsBoolean());
        assertEquals(code, envelope.getAsJsonObject("error").get("code").getAsString());
        assertFalse(response.body().contains(SECRET));
        assertTrue(envelope.has("id"));
        assertTrue(envelope.has("instance"));
    }

    @Test public void discoveryAndStatusNeverReturnCredentialMaterial() throws Exception {
        var catalog = request("GET", "/connections", null);
        assertEquals(200, catalog.statusCode());
        var rows = JsonParser.parseString(catalog.body()).getAsJsonObject().getAsJsonArray("result");
        assertEquals("reader", rows.get(0).getAsJsonObject().get("id").getAsString());
        assertEquals(java.util.Set.of("id", "kind", "backend", "permissions"),
            rows.get(0).getAsJsonObject().keySet());
        assertFalse(catalog.body().contains(SECRET));
        assertFalse(catalog.body().contains("private.invalid"));
        assertFalse(catalog.body().contains("private-username"));
        var status = request("GET", "/bsim/status?profile=reader", null);
        assertEquals(200, status.statusCode());
        assertFalse(status.body().contains(SECRET));
        assertFalse(status.body().contains("private.invalid"));
    }

    @Test public void queryOnlyProfileCannotEnterIngest() throws Exception {
        error(request("POST", "/bsim/ingest?profile=reader", null), 403,
            "CONNECTION_PERMISSION_DENIED");
    }

    @Test public void scriptOptInCannotBypassCredentialWorkerRestriction() throws Exception {
        error(request("POST", "/scripts/run", "{\"source\":\"anything\"}"), 403,
            "CONNECTION_WORKER_RESTRICTED");
        error(request("GET", "/scripts", null), 403, "CONNECTION_WORKER_RESTRICTED");
    }

    @Test public void nativeAndValidationExceptionsDoNotReachHttpClients() throws Exception {
        error(request("GET", "/test/native-failure", null), 500, "INTERNAL_ERROR");
        error(request("GET", "/test/invalid", null), 400, "BAD_REQUEST");
    }

    @After public void cleanup() throws Exception {
        if (server != null) server.stop();
        restore(ConnectionProfiles.PROPERTY, oldDirectory);
        restore(ScriptResource.PROPERTY, oldScripts);
        restore("ghidra.mcp.bind.host", oldBind);
        if (root != null) try (var files = Files.walk(root)) {
            for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }
    private static void restore(String key, String value) {
        if (value == null) System.clearProperty(key); else System.setProperty(key, value);
    }
}
