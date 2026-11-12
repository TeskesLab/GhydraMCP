package eu.starsong.ghidra.service;

import static org.junit.Assert.*;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.GhidraApplicationLayout;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.CategoryRecord;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.BSimFilter;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.JUnitCore;

/** Synthetic signatures through real H2/native QueryNearest: no decompiler or remote service. */
public class BSimMetadataFilterTest {
    private static final String EXECUTABLE = "target' OR '1'='1";
    private static final String ARCHITECTURE = "x86:LE:64:default";
    private static final String COMPILER = "gcc";
    private Path directory;
    private String previousDatabase;
    private Object connection;
    private Object info;
    private LSHVectorFactory vectors;
    private int settings;

    public static void main(String[] arguments) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(arguments[0])),
            new HeadlessGhidraApplicationConfiguration());
        var result = JUnitCore.runClasses(BSimMetadataFilterTest.class, BSimMultiQueryTest.class);
        for (var failure : result.getFailures()) failure.getException().printStackTrace();
        System.out.println("Native BSim metadata and multi-query protocols: " + result.getRunCount()
            + " executed, " + result.getFailureCount() + " failed");
        System.exit(result.wasSuccessful() ? 0 : 1);
    }

    @Before public void setup() throws Exception {
        directory = Files.createTempDirectory("bsim-native-metadata-");
        previousDatabase = System.getProperty(BSimService.PROPERTY_DATABASE);
        System.setProperty(BSimService.PROPERTY_DATABASE, directory.resolve("corpus").toString());
        Map<String, Object> opened = new LinkedHashMap<>();
        connection = BSimDatabase.open(BSimService.database(), true, opened);
        assertNotNull(opened.toString(), connection);
        assertTrue("must use actual native BSim, not the connection surrogate",
            connection.getClass().getProtectionDomain().getCodeSource().getLocation()
                .toString().endsWith("BSim.jar"));
        info = connection.getClass().getMethod("getInfo").invoke(connection);
        // Configuration is written via the native category protocol, never direct SQL.
        for (String category : List.of("Library", "Version")) {
            var install = new ghidra.features.bsim.query.protocol.InstallCategoryRequest();
            install.type_name = category;
            assertNotNull(install.execute((FunctionDatabase) connection));
        }
        info = connection.getClass().getMethod("getInfo").invoke(connection);
        vectors = (LSHVectorFactory) connection.getClass().getMethod("getLSHVectorFactory").invoke(connection);
        settings = vectors.getSettings();
        InsertRequest insert = new InsertRequest();
        configure(insert.manage);
        // Every excluded row scores better than target, and fails exactly one predicate.
        add(insert.manage, 1, "wrong_executable", "other", ARCHITECTURE, COMPILER, "libc", "1.0", 128);
        add(insert.manage, 2, "wrong_architecture", EXECUTABLE, "AARCH64:LE:64:v8A", COMPILER, "libc", "1.0", 128);
        add(insert.manage, 3, "wrong_compiler", EXECUTABLE, ARCHITECTURE, "clang", "libc", "1.0", 128);
        add(insert.manage, 4, "wrong_library", EXECUTABLE, ARCHITECTURE, COMPILER, "other", "1.0", 128);
        add(insert.manage, 5, "wrong_version", EXECUTABLE, ARCHITECTURE, COMPILER, "libc", "2.0", 128);
        add(insert.manage, 6, "wanted", EXECUTABLE, ARCHITECTURE, COMPILER, "libc", "1.0", 120);
        assertNotNull(String.valueOf(BSimDatabase.call(connection, "getLastError")),
            insert.execute((FunctionDatabase) connection));
    }

    private void configure(DescriptionManager manager) {
        manager.setVersion((short) 1, (short) 0);
        manager.setSettings(settings);
    }

    private FunctionDescription add(DescriptionManager manager, int id, String function,
            String executable, String architecture, String compiler, String library,
            String version, int count) throws Exception {
        var record = manager.newExecutableRecord(String.format("%032x", id), executable,
            compiler, architecture, new Date(0), null, null, null);
        var categories = new ArrayList<CategoryRecord>(2);
        categories.add(new CategoryRecord("Library", library));
        categories.add(new CategoryRecord("Version", version));
        manager.setExeCategories(record, categories);
        var description = manager.newFunctionDescription(function, 0x1000, record);
        int[] features = IntStream.rangeClosed(1, count).map(i -> i * 104729).toArray();
        var vector = vectors.buildVector(features);
        manager.attachSignature(description, manager.newSignature(vector, 1));
        return description;
    }

    private List<SimilarityNote> query(BSimMetadataFilter filter, int limit) throws Exception {
        QueryNearest query = new QueryNearest();
        configure(query.manage);
        add(query.manage, 100, "source", "source", ARCHITECTURE, COMPILER, "libc", "1.0", 128);
        query.max = limit;
        query.thresh = 0.1;
        query.signifthresh = -Double.MAX_VALUE;
        query.bsimFilter = (BSimFilter) filter.build(connection, info);
        var response = query.execute((FunctionDatabase) connection);
        assertNotNull(String.valueOf(BSimDatabase.call(connection, "getLastError")), response);
        List<SimilarityNote> result = new ArrayList<>();
        for (var group : response.result) for (var note : group) result.add(note);
        return result;
    }

    @After public void cleanup() throws Exception {
        if (connection != null) BSimDatabase.release(connection, BSimService.database());
        if (previousDatabase == null) System.clearProperty(BSimService.PROPERTY_DATABASE);
        else System.setProperty(BSimService.PROPERTY_DATABASE, previousDatabase);
        if (directory != null) try (var paths = Files.walk(directory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }

    @Test public void allPredicatesApplyBeforeLimitAndExcludedBetterScoresDoNotConsumeIt() throws Exception {
        var filter = BSimMetadataFilter.parse(EXECUTABLE, ARCHITECTURE, COMPILER,
            "{\"Library\":\"libc\",\"Version\":\"1.0\"}");
        var matches = query(filter, 1);
        assertEquals(1, matches.size());
        assertEquals("wanted", matches.get(0).getFunctionDescription().getFunctionName());
        assertTrue("fixture must have a weaker requested match", matches.get(0).getSimilarity() < 1.0);
        assertEquals(Map.of("executable", EXECUTABLE, "architecture", ARCHITECTURE,
            "compiler", COMPILER, "categories", Map.of("Library", "libc", "Version", "1.0")),
            filter.predicates());
        assertEquals(List.of("Library", "Version"), BSimMetadataFilter.availableCategories(info));
    }

    @Test public void twoCategoryNamesRequireBothNotEither() throws Exception {
        var filter = BSimMetadataFilter.parse(null, null, null,
            "{\"Library\":\"other\",\"Version\":\"2.0\"}");
        assertTrue(query(filter, 1).isEmpty());
    }


    @Test public void unfilteredNativeQueryKeepsItsOriginalLimitAndScores() throws Exception {
        var filter = BSimMetadataFilter.parse(null, null, null, null);
        assertNull(filter.build(connection, info));
        assertTrue(filter.predicates().isEmpty());
        var matches = query(filter, 1);
        assertEquals(1, matches.size());
        assertTrue(matches.get(0).getSimilarity() > 0.999);
        assertNotEquals("wanted", matches.get(0).getFunctionDescription().getFunctionName());
        assertEquals(6, query(filter, 20).size());
    }

    @Test public void unknownCategoriesAndUnsupportedBackendsRefuseInsteadOfBroadening() throws Exception {
        try {
            BSimMetadataFilter.parse(null, null, null, "{\"Unknown\":\"x\"}").build(connection, info);
            fail("unknown database category accepted");
        } catch (IllegalArgumentException expected) {
        }
        try {
            BSimMetadataFilter.parse("target", null, null, null).build(new Object(), info);
            fail("unsupported backend accepted");
        } catch (UnsupportedOperationException expected) {
        }
    }

    @Test public void malformedDuplicateBlankNonstringAndOversizedCategoriesRefuse() {
        for (String json : List.of("", "[]", "null", "{", "{} {}", "{Library:'libc'}",
                "{\"Library\":1}", "{\"Library\":null}", "{\"Library\":[\"libc\"]}",
                "{\"Library\":{}}", "{\"Library\":\"\"}", "{\" \":\"libc\"}",
                "{\"Library\":\"libc\",\"Library\":\"other\"}",
                "{\"Library\":\"" + "x".repeat(4097) + "\"}", " ".repeat(16385))) {
            try { BSimMetadataFilter.parse(null, null, null, json); fail("accepted: " + json); }
            catch (IllegalArgumentException expected) { /* fail closed before any native query */ }
        }
        String excessive = IntStream.range(0, 33)
            .mapToObj(i -> "\"Category" + i + "\":\"value\"")
            .collect(java.util.stream.Collectors.joining(",", "{", "}"));
        try { BSimMetadataFilter.parse(null, null, null, excessive); fail("accepted 33 categories"); }
        catch (IllegalArgumentException expected) { /* bounded predicate count */ }
        for (String value : List.of("", " ", "target ", "x\u0000y", "x".repeat(4097))) {
            try { BSimMetadataFilter.parse(value, null, null, null); fail("accepted executable"); }
            catch (IllegalArgumentException expected) { /* exact strings only */ }
        }
        assertTrue(BSimMetadataFilter.parse(null, null, null, "{}").predicates().isEmpty());
        var refused = BSimQueryService.queryWithFilters(null, null, null, 1, 0.7, 0,
            null, null, null, "{\"Library\":false}");
        assertEquals(Boolean.FALSE, refused.get("success"));
        assertEquals("BSIM_FILTER_INVALID", refused.get("code"));
        assertFalse(refused.containsKey("matches"));
    }
}
