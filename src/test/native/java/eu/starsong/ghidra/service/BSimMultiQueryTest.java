package eu.starsong.ghidra.service;

import static org.junit.Assert.*;
import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.util.GhidraSwing;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.*;

/** Real H2/native multi-source protocol, with synthetic signatures because stock decompiler may lack BSim. */
public class BSimMultiQueryTest {
    private final Object owner = new Object();
    private ProgramDB program;
    private Path directory;
    private Object connection;
    private LSHVectorFactory vectors;
    private String oldDatabase;
    private String oldProfiles;
    private final Map<String, Function> functions = new HashMap<>();
    private final AtomicInteger generators = new AtomicInteger();
    private final AtomicInteger scans = new AtomicInteger();
    private final AtomicInteger descriptions = new AtomicInteger();
    private final AtomicInteger closes = new AtomicInteger();

    @Before public void setup() throws Exception {
        oldDatabase = System.getProperty(BSimService.PROPERTY_DATABASE);
        oldProfiles = System.getProperty(ConnectionProfiles.PROPERTY);
        System.clearProperty(ConnectionProfiles.PROPERTY);
        directory = Files.createTempDirectory("bsim-native-multi-");
        System.setProperty(BSimService.PROPERTY_DATABASE, directory.resolve("corpus").toString());
        Map<String, Object> opened = new LinkedHashMap<>();
        connection = BSimDatabase.open(BSimService.database(), true, opened);
        assertNotNull(opened.toString(), connection);
        assertTrue("native protocol must precede connection surrogates", connection.getClass()
            .getProtectionDomain().getCodeSource().getLocation().toString().endsWith("BSim.jar"));
        vectors = (LSHVectorFactory) BSimDatabase.call(connection, "getLSHVectorFactory");
        var category = new ghidra.features.bsim.query.protocol.InstallCategoryRequest();
        category.type_name = "Version";
        assertNotNull(category.execute((FunctionDatabase) connection));
        InsertRequest insert = new InsertRequest();
        configure(insert.manage);
        add(insert.manage, "wanted", 1, "wanted", "gcc", "1", 128, 0);
        add(insert.manage, "excluded", 2, "other", "clang", "2", 128, 0);
        assertNotNull(insert.execute((FunctionDatabase) connection));
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        program = new ProgramDB("multi-source", language, language.getDefaultCompilerSpec(), owner);
        transaction(() -> {
            for (int i = 1; i <= 6; i++) {
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(i * 0x1000);
                program.getMemory().createInitializedBlock("text" + i, start, 16, (byte) 0, TaskMonitor.DUMMY, false);
                String name = List.of("alpha", "beta", "unrelated", "missing", "scan_error", "thunk").get(i - 1);
                Function function = program.getFunctionManager().createFunction(name, start,
                    new AddressSet(start, start.add(15)), SourceType.USER_DEFINED);
                functions.put(name, function);
            }
            functions.get("thunk").setThunkedFunction(functions.get("beta"));
            var namespace = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(), "nested", SourceType.USER_DEFINED);
            functions.get("beta").setParentNamespace(namespace);
        });
    }

    private void configure(DescriptionManager manager) {
        manager.setVersion((short) 1, (short) 0);
        manager.setSettings(vectors.getSettings());
    }

    private void add(DescriptionManager manager, String name, int id, String executable,
            String compiler, String version, int count, int shift) throws Exception {
        var record = manager.newExecutableRecord(String.format("%032x", id), executable,
            compiler, "x86:LE:64:default", new Date(0), null, null, null);
        manager.setExeCategories(record, new ArrayList<>(List.of(new ghidra.features.bsim.query.description.CategoryRecord("Version", version))));
        var function = manager.newFunctionDescription(name, 0x9000 + id, record);
        var vector = vectors.buildVector(IntStream.rangeClosed(1, count).map(i -> (i + shift) * 104729).toArray());
        manager.attachSignature(function, manager.newSignature(vector, 1));
    }

    private BSimMultiQueryService.SignatureFactory signatures(boolean mutate, boolean rejectQuery) {
        return (database, info, source) -> {
            generators.incrementAndGet();
            DescriptionManager manager = new DescriptionManager(); configure(manager);
            var executable = manager.newExecutableRecord("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "source",
                "gcc", "x86:LE:64:default", new Date(0), null, null, null);
            return new BSimMultiQueryService.Signatures() {
                public void scan(Function function) throws Exception {
                    scans.incrementAndGet();
                    String name = GhidraSwing.runRead(() -> function.getName(true));
                    long offset = GhidraSwing.runRead(() -> function.getEntryPoint().getOffset());
                    if (mutate) transaction(() -> functions.get("alpha").setName("mutated_alpha", SourceType.USER_DEFINED));
                    if (name.equals("scan_error")) throw new IllegalStateException("synthetic per-function scan failure");
                    if (name.equals("missing")) return;
                    int count = name.equals("alpha") ? 120 : 128;
                    int shift = name.equals("unrelated") ? 1000 : 0;
                    var description = manager.newFunctionDescription(name, offset, executable);
                    var vector = vectors.buildVector(IntStream.rangeClosed(1, count).map(i -> (i + shift) * 104729).toArray());
                    manager.attachSignature(description, manager.newSignature(vector, 1));
                }
                public Object descriptions() {
                    descriptions.incrementAndGet();
                    // Native fdbQueryNearest calls FunctionDatabase.checkSettingsForQuery:
                    // settings=0 is rejected as missing signature settings, without touching H2.
                    if (rejectQuery) manager.setSettings(0);
                    return manager;
                }
                public void close() { closes.incrementAndGet(); }
            };
        };
    }

    private Map<String, Object> run(String addresses, int offset, int count, int limit,
            Long expected, String executable, String categories) {
        return BSimMultiQueryService.run(program, addresses, offset, count, limit, 0.1, 0,
            expected, expected == null ? null : BSimMultiQueryService.programId(program),
            executable, null, null, categories, signatures(false, false));
    }
    @SuppressWarnings("unchecked") private static List<Map<String, Object>> rows(Map<String, Object> data) {
        return (List<Map<String, Object>>) data.get("results");
    }
    @SuppressWarnings("unchecked") private static List<Map<String, Object>> matches(Map<String, Object> row) {
        return (List<Map<String, Object>>) row.get("matches");
    }
    private static Map<String, Object> row(Map<String, Object> data, String function) {
        return rows(data).stream().filter(value -> Objects.equals(function, value.get("function"))).findFirst().orElseThrow();
    }
    private interface Work { void run() throws Exception; }
    private void transaction(Work work) throws Exception {
        GhidraSwing.runRead(() -> {
            int transaction = program.startTransaction("native multi-query fixture");
            try { work.run(); } finally { program.endTransaction(transaction, true); }
            return null;
        });
    }

    @After public void cleanup() throws Exception {
        if (program != null && !program.isClosed()) program.release(owner);
        if (connection != null) BSimDatabase.release(connection, directory.resolve("corpus").toString());
        if (oldDatabase == null) System.clearProperty(BSimService.PROPERTY_DATABASE);
        else System.setProperty(BSimService.PROPERTY_DATABASE, oldDatabase);
        if (oldProfiles == null) System.clearProperty(ConnectionProfiles.PROPERTY);
        else System.setProperty(ConnectionProfiles.PROPERTY, oldProfiles);
        if (directory != null) try (var paths = Files.walk(directory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }

    @Test public void pageIsAddressSelectedThenLocallyRankedWithOneGeneratorAndManager() {
        var data = run(null, 0, 2, 3, null, "wanted", null);
        assertEquals(data.toString(), true, data.get("success"));
        assertEquals(2, data.get("scanned")); assertEquals(2, data.get("searched"));
        assertEquals("nested::beta", rows(data).get(0).get("function"));
        assertEquals("alpha", rows(data).get(1).get("function"));
        assertEquals("ram::0x2000", rows(data).get(0).get("source_address"));
        assertEquals(2L, data.get("next_offset")); assertEquals(true, data.get("has_more"));
        assertEquals(false, data.get("complete"));
        assertEquals(1, generators.get()); assertEquals(2, scans.get());
        assertEquals(1, descriptions.get()); assertEquals(1, closes.get());
        var registry = new BSimMatchService(); registry.registerMulti(program, data);
        for (var source : rows(data)) for (var match : matches(source)) {
            var selected = registry.require(program, (String) match.get("match_id"));
            assertEquals(source.get("source_address"), selected.address());
            assertEquals(data.get("source_modification"), selected.modification());
        }
        var end = run(null, 6, 2, 1, ((Number) data.get("source_modification")).longValue(), null, null);
        assertTrue(rows(end).isEmpty()); assertNull(end.get("next_offset"));
        assertEquals(false, end.get("has_more")); assertEquals(true, end.get("complete"));
    }

    @Test public void missingEntriesSignaturesAndScanFailuresAreNeverNoMatches() {
        var data = run("[\"0x1000\",\"ram::0x3000\",\"0x4000\",\"0x5000\",\"0x6000\",\"0x7000\"]", 0, 0, 3, null, "wanted", null);
        assertEquals(6, data.get("scanned")); assertEquals(2, data.get("searched"));
        assertEquals("matched", row(data, "alpha").get("status"));
        assertEquals("error", row(data, "unrelated").get("status"));
        assertEquals("BSIM_QUERY_UNVERIFIED", row(data, "unrelated").get("code"));
        assertEquals("BSIM_SCAN_FAILED", row(data, "missing").get("code"));
        assertEquals("BSIM_SCAN_FAILED", row(data, "scan_error").get("code"));
        assertEquals("skipped", rows(data).get(4).get("status"));
        assertEquals("BSIM_NO_FUNCTION", rows(data).get(5).get("code"));
        assertEquals(false, data.get("complete"));
        assertEquals(1, generators.get()); assertEquals(4, scans.get());
    }

    @Test public void exactMetadataFiltersPrecedePerSourceLimit() {
        var data = BSimMultiQueryService.run(program, "[\"0x1000\",\"0x2000\"]", 0, 0, 1,
            0.1, 0, null, null, "wanted", "x86:LE:64:default", "gcc", "{\"Version\":\"1\"}", signatures(false, false));
        assertEquals(Map.of("executable", "wanted", "architecture", "x86:LE:64:default",
            "compiler", "gcc", "categories", Map.of("Version", "1")), data.get("filters"));
        assertEquals(List.of("Version"), data.get("available_categories"));
        for (var source : rows(data)) {
            assertEquals("wanted", matches(source).get(0).get("executable"));
            assertEquals(false, source.get("complete"));
        }
        var invalid = run("[\"0x1000\",\"0x2000\"]", 0, 0, 1, null, null, "{\"Unknown\":\"x\"}");
        for (var source : rows(invalid)) assertEquals("BSIM_FILTER_INVALID", source.get("code"));
        assertEquals(0, invalid.get("searched"));
    }

    @Test public void quotedExecutableRemainsLiteralInEverySourceQuery() throws Exception {
        String executable = "target' OR '1'='1";
        InsertRequest insert = new InsertRequest();
        configure(insert.manage);
        add(insert.manage, "quoted_wanted", 3, executable, "gcc", "1", 120, 0);
        assertNotNull(insert.execute((FunctionDatabase) connection));
        var data = BSimMultiQueryService.run(program, "[\"0x1000\",\"0x2000\"]", 0, 0, 1,
            0.1, 0, null, null, executable, "x86:LE:64:default", "gcc", "{\"Version\":\"1\"}",
            signatures(false, false));
        assertEquals(2, data.get("searched"));
        assertEquals(2, rows(data).size());
        for (var source : rows(data)) {
            assertEquals(1, matches(source).size());
            assertEquals(executable, matches(source).get(0).get("executable"));
            assertEquals("quoted_wanted", matches(source).get(0).get("function"));
        }
    }

    @Test public void malformedRequestsAndCanonicalDuplicatesFailBeforeOpeningGenerator() {
        for (String addresses : List.of("[]", "null", "{}", "[1]", "[\"\"]", "[\"0x1000\",\"0x1000\"]",
                "[\"0x1000\",\"ram::0x1000\"]", "[\"not an address\"]", " ".repeat(16385))) {
            var data = run(addresses, 0, 0, 1, null, null, null);
            assertEquals(addresses, "BSIM_BATCH_INVALID", data.get("code"));
        }
        for (int[] bounds : List.of(new int[]{-1, 50, 1}, new int[]{0, 101, 1}, new int[]{0, 50, 0},
                new int[]{0, 50, 11}, new int[]{0, 100, 3}))
            assertEquals("BSIM_BATCH_INVALID", run(null, bounds[0], bounds[1], bounds[2], null, null, null).get("code"));
        for (double threshold : List.of(Double.NaN, Double.POSITIVE_INFINITY, -0.1, 1.1))
            assertEquals("BSIM_BATCH_INVALID", BSimMultiQueryService.run(program, "[\"0x1000\"]", 0, 0, 1,
                threshold, 0, null, null, null, null, null, null, signatures(false, false)).get("code"));
        String excessive = IntStream.range(0, 101).mapToObj(i -> "\"0x" + Integer.toHexString(i) + "\"")
            .collect(java.util.stream.Collectors.joining(",", "[", "]"));
        assertEquals("BSIM_BATCH_INVALID", run(excessive, 0, 0, 1, null, null, null).get("code"));
        assertEquals(0, generators.get());
    }

    @Test public void staleExpectedStampAndMidScanMutationRefuseAllResults() {
        try {
            run(null, 0, 2, 1, program.getModificationNumber() + 1, null, null);
            fail("stale page accepted");
        } catch (ConnectionException stale) { assertEquals("BSIM_MATCH_STALE", stale.code()); }
        assertEquals(0, generators.get());
        try {
            BSimMultiQueryService.run(program, "[\"0x1000\",\"0x2000\"]", 0, 0, 1, 0.1, 0,
                null, null, null, null, null, null, signatures(true, false));
            fail("mutating scan returned results");
        } catch (ConnectionException stale) { assertEquals("BSIM_MATCH_STALE", stale.code()); }
        assertEquals(1, closes.get()); assertFalse(program.isClosed());
    }

    @Test public void backendOpenAndExecutionFailuresAreExplicitPerSourceErrors() {
        System.setProperty(BSimService.PROPERTY_DATABASE, directory.resolve("absent").toString());
        var absent = run("[\"0x1000\",\"0x2000\"]", 0, 0, 3, null, null, null);
        for (var source : rows(absent)) {
            assertEquals("error", source.get("status")); assertEquals("BSIM_NO_DATABASE", source.get("code"));
            assertTrue(matches(source).isEmpty());
        }
        assertEquals(0, absent.get("searched")); assertEquals(false, absent.get("complete"));
        System.setProperty(BSimService.PROPERTY_DATABASE, directory.resolve("corpus").toString());
        var failed = BSimMultiQueryService.run(program, "[\"0x1000\",\"0x2000\"]", 0, 0, 3, 0.1, 0,
            null, null, null, null, null, null, signatures(false, true));
        for (var source : rows(failed)) {
            assertEquals("error", source.get("status")); assertEquals("BSIM_QUERY_FAILED", source.get("code"));
            assertTrue(matches(source).isEmpty());
        }
    }

    @Test public void qualifiedSpacesWithSameOffsetUseFullNativeNameAndAmbiguousOnesRefuse() throws Exception {
        final Function[] overlay = new Function[1];
        transaction(() -> {
            var start = functions.get("alpha").getEntryPoint();
            var block = program.getMemory().createInitializedBlock("overlay", start, 16, (byte) 0, TaskMonitor.DUMMY, true);
            overlay[0] = program.getFunctionManager().createFunction("overlay_alpha", block.getStart(),
                new AddressSet(block.getStart(), block.getEnd()), SourceType.USER_DEFINED);
        });
        String qualified = BSimMatchService.qualifiedAddress(overlay[0]);
        var data = run("[\"ram::0x1000\",\"" + qualified + "\"]", 0, 0, 3, null, "wanted", null);
        var registry = new BSimMatchService(); registry.registerMulti(program, data);
        for (var source : rows(data)) {
            assertEquals("matched", source.get("status"));
            String id = (String) matches(source).get(0).get("match_id");
            assertEquals(source.get("source_address"), registry.require(program, id).address());
        }
        transaction(() -> overlay[0].setName("alpha", SourceType.USER_DEFINED));
        var ambiguous = run("[\"ram::0x1000\",\"" + qualified + "\"]", 0, 0, 3, null, null, null);
        for (var source : rows(ambiguous)) assertEquals("BSIM_SOURCE_AMBIGUOUS", source.get("code"));
        assertEquals(0, ambiguous.get("searched"));
    }

    @Test public void externalSkipsParticipateInOrderedPagesWithoutScanning() throws Exception {
        List<Function> all = new ArrayList<>(functions.values());
        transaction(() -> {
            for (String name : List.of("z_external", "a_external", "middle_external")) {
                var location = program.getExternalManager().addExtFunction("library", name, null, SourceType.USER_DEFINED);
                all.add(location.getFunction());
            }
        });
        all.sort(Comparator.comparing(Function::getEntryPoint));
        long stamp = program.getModificationNumber();
        for (int offset = 0; offset < all.size(); offset++) {
            var data = run(null, offset, 1, 1, stamp, null, null);
            var source = rows(data).get(0);
            assertEquals(BSimMatchService.qualifiedAddress(all.get(offset)), source.get("source_address"));
            assertEquals(offset + 1 < all.size(), data.get("has_more"));
            if (all.get(offset).isExternal()) {
                assertEquals("skipped", source.get("status"));
                assertEquals(0, data.get("searched"));
                assertEquals(List.of("Version"), data.get("available_categories"));
            }
        }
    }

    @Test public void nativeSelfSignificanceSkipDoesNotClaimACorpusSearch() {
        var data = BSimMultiQueryService.run(program, "[\"0x1000\",\"0x2000\"]", 0, 0, 3,
            0.1, Double.MAX_VALUE, null, null, null, null, null, null, signatures(false, false));
        assertEquals(0, data.get("searched"));
        for (var source : rows(data)) {
            assertEquals("skipped", source.get("status"));
            assertEquals("BSIM_BELOW_THRESHOLD", source.get("code"));
        }
        assertEquals(false, data.get("complete"));
    }

    @Test public void twoHundredSelectionsRemainLiveAndRetainRequestProfileAcrossEdt() throws Exception {
        var profiles = directory.resolve("profiles"); Files.createDirectory(profiles);
        Files.setPosixFilePermissions(profiles, PosixFilePermissions.fromString("rwx------"));
        for (var entry : Map.of(".lock", "", "profiles.json", "{\"version\":1,\"profiles\":{\"a\":{\"kind\":\"bsim\",\"backend\":\"h2\",\"endpoint\":\""
                + directory.resolve("corpus") + "\",\"auth\":\"none\",\"permissions\":[\"query\"]}}}").entrySet()) {
            Path file = profiles.resolve(entry.getKey()); Files.writeString(file, entry.getValue());
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        }
        System.setProperty(ConnectionProfiles.PROPERTY, profiles.toString());
        var registry = new BSimMatchService();
        ConnectionProfiles.withProfile("a", "bsim", "query", profile -> {
            var data = run("[\"0x1000\",\"0x2000\"]", 0, 0, 3, null, "wanted", null);
            for (var source : rows(data)) {
                var template = new LinkedHashMap<>(matches(source).get(0));
                matches(source).clear();
                for (int i = 0; i < 100; i++) matches(source).add(new LinkedHashMap<>(template));
            }
            registry.registerMulti(program, data);
            Set<String> ids = new HashSet<>();
            for (var source : rows(data)) for (var match : matches(source)) {
                String id = (String) match.get("match_id"); assertTrue(ids.add(id));
                var selected = registry.require(program, id);
                assertEquals("a", selected.profile()); assertEquals(source.get("source_address"), selected.address());
            }
            assertEquals(200, ids.size());
            return null;
        });
    }

    @Test public void staleBatchRegistrationPublishesNoPartialCandidateIds() throws Exception {
        var data = run("[\"0x1000\",\"0x2000\"]", 0, 0, 3, null, "wanted", null);
        transaction(() -> functions.get("alpha").setName("changed_before_registration", SourceType.USER_DEFINED));
        try {
            new BSimMatchService().registerMulti(program, data);
            fail("stale batch candidates were registered");
        } catch (ConnectionException stale) { assertEquals("BSIM_MATCH_STALE", stale.code()); }
        for (var source : rows(data)) for (var match : matches(source)) assertFalse(match.containsKey("match_id"));
    }

    @Test public void malformedNativeSourceCorrelationRefusesInsteadOfGuessing() throws Exception {
        var manager = new DescriptionManager(); configure(manager);
        add(manager, "unexpected", 9, "unexpected", "gcc", "1", 128, 0);
        var query = new ghidra.features.bsim.query.protocol.QueryNearest();
        var response = new ghidra.features.bsim.query.protocol.ResponseNearest(query);
        response.totalfunc = 1;
        var unexpected = manager.listAllFunctions().next();
        response.result.add(new ghidra.features.bsim.query.protocol.SimilarityResult(unexpected));
        var row = new LinkedHashMap<String, Object>();
        row.put("matches", new ArrayList<>()); row.put("success", false);
        var expected = new BSimMultiQueryService.Source(functions.get("alpha"),
            new BSimMultiQueryService.Identity(0x1000, "alpha"), functions.get("alpha").getEntryPoint(), row);
        try {
            GhidraSwing.runRead(() -> { BSimMultiQueryService.correlate(response, List.of(expected), 3); return null; });
            fail("unknown native source was attached to a function");
        } catch (IllegalStateException refused) { assertTrue(refused.getMessage().contains("unknown")); }
        assertFalse(Boolean.TRUE.equals(row.get("success")));
    }

    @Test public void sameStampDifferentProgramInstanceCannotContinueAndLegacyStampIsRejected() throws Exception {
        var language = program.getLanguage();
        ProgramDB first = new ProgramDB("same-name", language, language.getDefaultCompilerSpec(), owner);
        ProgramDB second = new ProgramDB("same-name", language, language.getDefaultCompilerSpec(), owner);
        try {
            assertEquals(first.getModificationNumber(), second.getModificationNumber());
            var initial = BSimMultiQueryService.run(first, null, 0, 1, 1, 0.1, 0,
                null, null, null, null, null, null, signatures(false, false));
            String id = (String) initial.get("source_program_id");
            assertNotNull(id);
            long stamp = ((Number) initial.get("source_modification")).longValue();
            var continued = BSimMultiQueryService.run(first, null, 1, 1, 1, 0.1, 0,
                stamp, id, null, null, null, null, signatures(false, false));
            assertEquals(id, continued.get("source_program_id"));
            assertEquals("BSIM_BATCH_INVALID", BSimMultiQueryService.run(second, null, 1, 1, 1, 0.1, 0,
                stamp, null, null, null, null, null, signatures(false, false)).get("code"));
            try {
                BSimMultiQueryService.run(second, null, 1, 1, 1, 0.1, 0,
                    stamp, id, null, null, null, null, signatures(false, false));
                fail("different Program instance with identical name and stamp accepted");
            } catch (ConnectionException stale) { assertEquals("BSIM_MATCH_STALE", stale.code()); }
            assertNotEquals(id, BSimMultiQueryService.programId(second));
        } finally {
            first.release(owner); second.release(owner);
        }
    }

    @Test public void submittedCountDoesNotProveOmittedVectorTasksSucceeded() throws Exception {
        // H2 sets totalvec before parallel work, swallows task exceptions, then
        // copies totalvec to totalfunc even when the response has missing groups.
        var response = new ghidra.features.bsim.query.protocol.ResponseNearest(
            new ghidra.features.bsim.query.protocol.QueryNearest());
        response.totalfunc = 1;
        var source = syntheticSource("alpha");
        BSimMultiQueryService.correlate(response, List.of(source), 3);
        assertEquals("error", source.row().get("status"));
        assertEquals("BSIM_QUERY_UNVERIFIED", source.row().get("code"));
        assertEquals(false, source.row().get("success"));
        assertEquals(false, source.row().get("complete"));
    }

    public static class PreciseNote {
        private final double similarity, significance;
        PreciseNote(double similarity, double significance) {
            this.similarity = similarity; this.significance = significance;
        }
        public double getSimilarity() { return similarity; }
        public double getSignificance() { return significance; }
        public Object getFunctionDescription() { return null; }
    }
    public static class PreciseGroup extends ArrayList<PreciseNote> {
        private final Object base;
        PreciseGroup(Object base, PreciseNote... notes) { this.base = base; addAll(List.of(notes)); }
        public Object getBase() { return base; }
        public int getTotalCount() { return size(); }
    }
    public static class PreciseResponse {
        public int totalfunc;
        public List<PreciseGroup> result = new ArrayList<>();
    }
    private BSimMultiQueryService.Source syntheticSource(String name) {
        Function function = functions.get(name);
        var row = new LinkedHashMap<String, Object>();
        row.put("source_address", BSimMatchService.qualifiedAddress(function));
        row.put("matches", new ArrayList<>());
        return new BSimMultiQueryService.Source(function,
            new BSimMultiQueryService.Identity(function.getEntryPoint().getOffset(), function.getName(true)),
            function.getEntryPoint(), row);
    }

    @Test public void candidateAndOverviewRankingPrecedeDisplayRounding() throws Exception {
        var manager = new DescriptionManager(); configure(manager);
        var executable = manager.newExecutableRecord("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "source",
            "gcc", "x86:LE:64:default", new Date(0), null, null, null);
        var alpha = syntheticSource("alpha");
        var beta = syntheticSource("beta");
        var alphaDescription = manager.newFunctionDescription("alpha", 0x1000, executable);
        var betaDescription = manager.newFunctionDescription("nested::beta", 0x2000, executable);
        var lower = new PreciseNote(0.9001, 100.0001);
        var higher = new PreciseNote(0.9002, 1.0001);
        var betaBest = new PreciseNote(0.9003, 0.0001);
        var response = new PreciseResponse(); response.totalfunc = 2;
        response.result.add(new PreciseGroup(alphaDescription, lower, higher));
        response.result.add(new PreciseGroup(betaDescription, betaBest));
        BSimMultiQueryService.correlate(response, List.of(alpha, beta), 1);
        assertEquals(0.9002, ((Number) matches(alpha.row()).get(0).get("similarity")).doubleValue(), 0);
        var rows = new ArrayList<>(List.of(alpha.row(), beta.row()));
        BSimMultiQueryService.rank(List.of(alpha, beta), rows);
        assertSame(beta.row(), rows.get(0));
        BSimMultiQueryService.roundScores(rows);
        assertEquals(0.9, ((Number) matches(rows.get(0)).get(0).get("similarity")).doubleValue(), 0);
        assertEquals(0.9, ((Number) matches(rows.get(1)).get(0).get("similarity")).doubleValue(), 0);
        // Equal native similarity still uses unrounded significance as the secondary key.
        response.result.clear();
        response.result.add(new PreciseGroup(alphaDescription,
            new PreciseNote(0.9, 1.0001), new PreciseNote(0.9, 1.0002)));
        response.result.add(new PreciseGroup(betaDescription, new PreciseNote(0.9, 1.0003)));
        BSimMultiQueryService.correlate(response, List.of(alpha, beta), 1);
        assertEquals(1.0002, ((Number) matches(alpha.row()).get(0).get("significance")).doubleValue(), 0);
        rows = new ArrayList<>(List.of(alpha.row(), beta.row()));
        BSimMultiQueryService.rank(List.of(alpha, beta), rows);
        assertSame(beta.row(), rows.get(0));
        BSimMultiQueryService.roundScores(rows);
        assertEquals(1.0, ((Number) matches(rows.get(0)).get(0).get("significance")).doubleValue(), 0);
    }
}
