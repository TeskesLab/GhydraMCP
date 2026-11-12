package eu.starsong.ghidra.server;

import static org.junit.Assert.*;
import com.google.gson.JsonParser;
import eu.starsong.ghidra.resource.InstanceResource;
import eu.starsong.ghidra.resource.AnalysisResource;
import eu.starsong.ghidra.resource.BSimResource;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.Test;

public class HeadlessInstanceTest {
    @Test public void selectedProgramReplacesBootstrapInstanceMetadata() throws Exception {
        Object owner = new Object();
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB("selected-repository-program", language,
            language.getDefaultCompilerSpec(), owner);
        var instances = new ConcurrentHashMap<Integer, Object>();
        instances.put(0, Map.of("port", 0, "headless", true, "file", "bootstrap-program"));
        var server = new GhydraServer(null, 0, instances, true);
        server.register(new InstanceResource());
        server.register((app, contexts) -> app.post("/select", request -> {
            contexts.apply(request).activateProgram(program, null);
            request.status(204);
        }));
        server.start();
        var client = HttpClient.newHttpClient();
        URI base = URI.create("http://127.0.0.1:" + server.app().port());
        try {
            var selected = client.send(HttpRequest.newBuilder(base.resolve("/select"))
                .header("Origin", "http://localhost")
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(204, selected.statusCode());
            var response = client.send(HttpRequest.newBuilder(base.resolve("/instances/0")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
            assertEquals(response.body(), 200, response.statusCode());
            var snapshot = JsonParser.parseString(response.body()).getAsJsonObject().getAsJsonObject("result");
            assertEquals("selected-repository-program", snapshot.get("file").getAsString());
            assertEquals("x86:LE:64:default", snapshot.get("architecture").getAsString());
            assertEquals(program.getImageBase().toString(), snapshot.get("imageBase").getAsString());
        } finally {
            server.stop();
            server.releaseActiveProgram();
            program.release(owner);
        }
        assertTrue(program.isClosed());
    }
    @Test public void readonlyCompatibilityViewRejectsAnalysisBeforeScheduling() throws Exception {
        Object owner = new Object();
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB("readonly-analysis", language,
            language.getDefaultCompilerSpec(), owner);
        assertTrue("The guard must protect a natively changeable view", program.isChangeable());
        ManagedProgramGuard.registerReadOnly(program);
        var server = new GhydraServer(null, 0, new ConcurrentHashMap<>(), true);
        server.register(new AnalysisResource());
        server.register((app, contexts) -> app.post("/select", request -> {
            contexts.apply(request).activateProgram(program, null);
            request.status(204);
        }));
        server.start();
        var client = HttpClient.newHttpClient();
        URI base = URI.create("http://127.0.0.1:" + server.app().port());
        try {
            var selected = client.send(HttpRequest.newBuilder(base.resolve("/select"))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(204, selected.statusCode());
            var response = client.send(HttpRequest.newBuilder(base.resolve("/analysis/run"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(response.body(), 403, response.statusCode());
            var error = JsonParser.parseString(response.body()).getAsJsonObject().getAsJsonObject("error");
            assertEquals("REPOSITORY_READ_ONLY", error.get("code").getAsString());
        } finally {
            server.stop();
            server.releaseActiveProgram();
            program.release(owner);
        }
        assertTrue(program.isClosed());
    }
    @Test public void boundedBatchJsonAndUnicodeFiltersReachTheRealResource() throws Exception {
        Object owner = new Object();
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB("large-batch-query", language,
            language.getDefaultCompilerSpec(), owner);
        String address;
        int transaction = program.startTransaction("Create external source");
        try {
            var function = program.getExternalManager()
                .addExtFunction("imports", "external_only", null, SourceType.USER_DEFINED).getFunction();
            var entry = function.getEntryPoint();
            address = entry.getAddressSpace().getName() + "::0x" + Long.toHexString(entry.getOffset());
        } finally { program.endTransaction(transaction, true); }
        var server = new GhydraServer(null, 0, new ConcurrentHashMap<>(), false, program, null);
        server.register(new BSimResource());
        try {
            server.start();
            var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            String entries = "[\"" + address + "\"]";
            entries = " ".repeat(16384 - entries.length()) + entries;
            String unicode = "\u0800".repeat(4096);
            String categories = "{\"Version\":\"" + unicode + "\"}";
            categories += " ".repeat(16384 - categories.length());
            String base = "http://127.0.0.1:" + server.app().port() + "/bsim/batch-query?addresses="
                + URLEncoder.encode(entries, StandardCharsets.UTF_8);
            String filters = "&executable=" + URLEncoder.encode(unicode, StandardCharsets.UTF_8)
                + "&architecture=" + URLEncoder.encode(unicode, StandardCharsets.UTF_8)
                + "&compiler=" + URLEncoder.encode(unicode, StandardCharsets.UTF_8)
                + "&categories=" + URLEncoder.encode(categories, StandardCharsets.UTF_8);
            for (String query : new String[] { base, base + filters }) {
                var response = client.send(HttpRequest.newBuilder(URI.create(query))
                    .timeout(Duration.ofSeconds(15)).GET().build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(response.body(), 200, response.statusCode());
                var envelope = JsonParser.parseString(response.body()).getAsJsonObject();
                assertTrue(envelope.get("success").getAsBoolean());
                var result = envelope.getAsJsonObject("result");
                assertEquals(1, result.get("scanned").getAsInt());
                assertEquals(0, result.get("searched").getAsInt());
                var source = result.getAsJsonArray("results").get(0).getAsJsonObject();
                assertEquals(address, source.get("source_address").getAsString());
                assertEquals("skipped", source.get("status").getAsString());
                assertEquals("BSIM_NO_BODY", source.get("code").getAsString());
                assertFalse(result.get("complete").getAsBoolean());
            }
        } finally {
            server.stop();
            server.releaseActiveProgram();
            program.release(owner);
        }
        assertTrue(program.isClosed());
    }
}
