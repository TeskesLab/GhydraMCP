package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.connection.Profile;
import eu.starsong.ghidra.server.ManagedProgramGuard;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import javax.swing.SwingUtilities;
import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

/** Native ProgramDB/decompiler evidence plus deterministic repository handles; no server or credentials. */
public class BSimReferenceInspectionTest {
    private static final String MD5 = "3533f690ac55480d83672c91b3762e36";
    private static final String MATCH_ID = "8ca7ab96-f8ae-4f64-bbb2-7d7b1bb2f483";

    private static Map<String, Object> match() {
        return new LinkedHashMap<>(Map.of("match_id", MATCH_ID, "repository_url",
            "ghidra://EXAMPLE.invalid/repository/program", "executable_md5", MD5,
            "address", "ram::0x1000", "function", "indexed_original_name"));
    }

    private static final class Fixture implements AutoCloseable {
        final Object owner = new Object();
        final Path root = Files.createTempDirectory("ghydra-reference-test-");
        final ProgramDB program;
        final Function function;
        final RepositoryService service;
        final List<String> grants = new ArrayList<>();
        int readonlyOpens;
        int requestedVersion;
        int forbiddenCalls;
        boolean linkedFile;
        boolean linkedFolder;
        boolean workspaceClosed;

        Fixture() throws Exception {
            program = GhidraSwing.runRead(() -> {
                var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
                ProgramDB db = new ProgramDB("reference", language, language.getDefaultCompilerSpec(), owner);
                int tx = db.startTransaction("native fixture");
                try {
                    db.setExecutableMD5(MD5);
                    Address start = db.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                    byte[] bytes = { (byte) 0xb8, 42, 0, 0, 0, (byte) 0xc3 }; // mov eax,42; ret
                    var block = db.getMemory().createInitializedBlock("text", start,
                        new ByteArrayInputStream(bytes), bytes.length, TaskMonitor.DUMMY, false);
                    block.setExecute(true);
                    DisassembleCommand disassemble = new DisassembleCommand(start, null, true);
                    disassemble.enableCodeAnalysis(false);
                    assertTrue(disassemble.applyTo(db, TaskMonitor.DUMMY));
                    Function created = db.getFunctionManager().createFunction("current_name", start,
                        new AddressSet(start, start.add(bytes.length - 1)), SourceType.USER_DEFINED);
                    created.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                    created.setComment("Current reference annotation");
                } finally { db.endTransaction(tx, true); }
                return db;
            });
            function = GhidraSwing.runRead(() -> program.getFunctionManager().getFunctionAt(
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)));
            DomainFile file = proxy(DomainFile.class, (p, method, args) -> switch (method.getName()) {
                case "getDomainObjectClass" -> Program.class;
                case "exists", "isVersioned" -> true;
                case "isLink" -> linkedFile;
                case "getLatestVersion", "getVersion" -> 7;
                case "getPathname" -> "/program";
                case "getReadOnlyDomainObject" -> {
                    assertFalse(SwingUtilities.isEventDispatchThread());
                    readonlyOpens++;
                    requestedVersion = (int) args[1];
                    assertTrue(program.addConsumer(args[0]));
                    yield program;
                }
                case "getDomainObject", "checkout", "checkin", "save" -> {
                    forbiddenCalls++;
                    throw new AssertionError("Inspect must not open writable, checkout, checkin, or save");
                }
                default -> zero(method.getReturnType());
            });
            DomainFolder folder = proxy(DomainFolder.class, (p, method, args) -> switch (method.getName()) {
                case "getFile" -> "program".equals(args[0]) ? file : null;
                case "getFolder" -> "linked".equals(args[0]) ? p : null;
                case "isLinked" -> linkedFolder;
                default -> zero(method.getReturnType());
            });
            ProjectData data = proxy(ProjectData.class, (p, method, args) -> switch (method.getName()) {
                case "getRootFolder" -> folder;
                default -> zero(method.getReturnType());
            });
            Project project = proxy(Project.class, (p, method, args) -> switch (method.getName()) {
                case "getProjectData" -> data;
                default -> zero(method.getReturnType());
            });
            Profile profile = new Profile("reader", "ghidra", "ghidra",
                "ghidra://example.invalid:13100/repository", "none", null,
                Set.of("read", "checkout", "checkin"));
            RepositoryService.Access access = new RepositoryService.Access() {
                public Path directory() { return root; }
                public <T> T call(String id, String grant, java.util.function.Function<Profile, T> operation) {
                    assertEquals("reader", id);
                    grants.add(grant);
                    return operation.apply(profile);
                }
            };
            service = new RepositoryService(access, (p, directory) -> new RepositoryService.Workspace() {
                public Project project() { return project; }
                public boolean readOnly() { return false; }
                public void refresh() {}
                public void close() { workspaceClosed = true; }
            }, "reference-test");
        }

        @Override public void close() throws Exception {
            service.close();
            program.release(owner);
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    @Test public void selectedIdentityUsesOnlyReadonlyConcreteVersionWithoutActivationOrCheckout() throws Exception {
        try (Fixture fixture = new Fixture()) {
            long stamp = GhidraSwing.runRead(fixture.program::getModificationNumber);
            List<Object> consumers = GhidraSwing.runRead(fixture.program::getConsumerList);
            Map<String, Object> response = fixture.service.inspectMatch("reader", match(), -1, 1000);
            assertEquals(true, response.get("identity_verified"));
            assertEquals(MATCH_ID, response.get("match_id"));
            assertEquals("/program", response.get("path"));
            assertEquals(7, response.get("version"));
            assertEquals(true, response.get("name_changed"));
            assertEquals(List.of("read"), fixture.grants);
            assertEquals(1, fixture.readonlyOpens);
            assertEquals(7, fixture.requestedVersion);
            assertEquals(0, fixture.forbiddenCalls);
            assertEquals(consumers, GhidraSwing.runRead(fixture.program::getConsumerList));
            assertTrue(ManagedProgramGuard.isManaged(fixture.program));
            assertEquals(stamp, (long) GhidraSwing.runRead(fixture.program::getModificationNumber));
            fixture.service.close();
            assertTrue("Temporary reference must not enter retained active-program cache", fixture.workspaceClosed);
            assertFalse(fixture.program.isClosed());
        }
    }

    @Test public void nativeExportUsesExactReadonlyResolverAndCompleteBoundedGdt() throws Exception {
        try (Fixture fixture = new Fixture()) {
            long modification = fixture.program.getModificationNumber();
            Map<String, Object> result = fixture.service.exportMatch("reader", match(), -1);
            assertEquals(true, result.get("identity_verified"));
            assertEquals(7, result.get("version"));
            assertEquals(MATCH_ID, result.get("match_id"));
            Map<?, ?> identity = (Map<?, ?>) result.get("identity");
            assertEquals("ram::0x1000", identity.get("selected_address"));
            assertEquals("ram::0x1000", identity.get("address"));
            Map<?, ?> archive = (Map<?, ?>) result.get("archive");
            assertEquals("ghidra-gdt-v1", archive.get("format"));
            byte[] bytes = java.util.Base64.getDecoder().decode((String) archive.get("gdt_base64"));
            assertTrue(bytes.length <= BSimSignatureTransfer.MAX_ARCHIVE_BYTES);
            assertEquals(bytes.length, archive.get("size"));
            assertEquals(BSimSignatureTransfer.digest(bytes), archive.get("sha256"));
            try (var opened = new BSimSignatureTransfer.OpenArchive(bytes, (String) archive.get("root_type"), List.of())) {
                assertEquals("int", opened.root.getReturnType().getName());
                assertNull(opened.root.getComment());
                assertEquals(8, opened.manager.getDataOrganization().getPointerSize());
            }
            assertEquals(1, fixture.readonlyOpens);
            assertEquals(7, fixture.requestedVersion);
            assertEquals(0, fixture.forbiddenCalls);
            assertEquals(List.of("read"), fixture.grants);
            assertEquals(modification, fixture.program.getModificationNumber());
            assertEquals(List.of(fixture.owner), fixture.program.getConsumerList());
            Map<String, Object> wrong = match(); wrong.put("executable_md5", "0".repeat(32));
            expect("BSIM_REFERENCE_IDENTITY_MISMATCH", () -> fixture.service.exportMatch("reader", wrong, -1));
        }
    }

    @Test public void wrongMd5NeverProducesEvidenceAndReleasesTemporaryConsumer() throws Exception {
        try (Fixture fixture = new Fixture()) {
            Map<String, Object> selected = match();
            selected.put("executable_md5", "00000000000000000000000000000000");
            expect("BSIM_REFERENCE_IDENTITY_MISMATCH", () -> fixture.service.inspectMatch("reader", selected, -1, 1000));
            assertEquals(1, fixture.readonlyOpens);
            assertEquals(List.of(fixture.owner), fixture.program.getConsumerList());
            assertEquals(0, fixture.forbiddenCalls);
        }
    }

    @Test public void unsafeAndOutOfScopeUrlsCannotOpenNativeFiles() throws Exception {
        try (Fixture fixture = new Fixture()) {
            for (String url : List.of("https://example.invalid/repository/program",
                    "ghidra://user@example.invalid/repository/program",
                    "ghidra://example.invalid/repository/../program",
                    "ghidra://example.invalid/repository/%2e%2e/program",
                    "ghidra://example.invalid/repository/program?q=secret",
                    "ghidra://example.invalid/repository/program#ram:1000",
                    "ghidra://example.invalid/other/program",
                    "ghidra://example.invalid:13101/repository/program")) {
                Map<String, Object> selected = match();
                selected.put("repository_url", url);
                try { fixture.service.inspectMatch("reader", selected, -1, 1000); fail(url); }
                catch (ConnectionException | RepositoryService.RepositoryException expected) {}
            }
            assertEquals(0, fixture.readonlyOpens);
            assertEquals(0, fixture.forbiddenCalls);
        }
    }

    @Test public void linkingFilesAndFoldersAreRejectedWithoutFollowing() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.linkedFile = true;
            expectRepository("REPOSITORY_NOT_FOUND", () -> fixture.service.inspectMatch("reader", match(), -1, 1000));
            fixture.linkedFile = false;
            fixture.linkedFolder = true;
            Map<String, Object> selected = match();
            selected.put("repository_url", "ghidra://example.invalid/repository/linked/program");
            expectRepository("REPOSITORY_NOT_FOUND", () -> fixture.service.inspectMatch("reader", selected, -1, 1000));
            assertEquals(0, fixture.readonlyOpens);
        }
    }

    @Test public void nativeSnapshotContainsExactAddressSignatureTypesAndRealCode() throws Exception {
        try (Fixture fixture = new Fixture()) {
            Map<String, Object> snapshot = BSimFunctionSnapshot.capture(fixture.program, fixture.function, 1000);
            Map<?, ?> function = (Map<?, ?>) snapshot.get("function");
            assertEquals("current_name", function.get("name"));
            assertEquals("ram::0x1000", function.get("address"));
            assertEquals("Current reference annotation", function.get("comment"));
            Map<?, ?> types = (Map<?, ?>) snapshot.get("types");
            Map<?, ?> returnType = (Map<?, ?>) types.get(function.get("return_type"));
            assertEquals("int", returnType.get("name"));
            assertEquals(4, returnType.get("length"));
            assertEquals(true, snapshot.get("types_complete"));
            Map<?, ?> code = (Map<?, ?>) snapshot.get("code");
            assertEquals(code.toString(), true, code.get("complete"));
            assertNull(code.get("error"));
            assertTrue(((String) code.get("text")).contains("42") || ((String) code.get("text")).contains("0x2a"));
            Map<?, ?> truncated = (Map<?, ?>) BSimFunctionSnapshot.capture(fixture.program, fixture.function, 1).get("code");
            assertEquals(false, truncated.get("complete"));
            assertNotNull(truncated.get("error"));
            assertNotNull(truncated.get("text"));
        }
    }

    @Test public void readonlyHttpInspectionAllowsOnlyBoundFlatGetParameters() throws Exception {
        String property = eu.starsong.ghidra.middleware.ReadOnlyGuard.PROPERTY;
        String previous = System.getProperty(property);
        System.setProperty(property, "true");
        try (Fixture fixture = new Fixture()) {
            var server = new eu.starsong.ghidra.server.GhydraServer(null, 0, new HashMap<>(), false);
            server.register(new eu.starsong.ghidra.resource.RepositoryResource(fixture.service));
            server.start();
            try {
                var client = java.net.http.HttpClient.newHttpClient();
                StringBuilder query = new StringBuilder("profile=reader");
                for (var entry : match().entrySet()) query.append('&').append(entry.getKey()).append('=')
                    .append(java.net.URLEncoder.encode((String) entry.getValue(), java.nio.charset.StandardCharsets.UTF_8));
                var uri = java.net.URI.create("http://127.0.0.1:" + server.app().port()
                    + "/repositories/inspect-match?" + query);
                var response = client.send(java.net.http.HttpRequest.newBuilder(uri).GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
                assertEquals(response.body(), 200, response.statusCode());
                assertTrue(response.body().contains("\"identity_verified\":true"));
                var exportUri = java.net.URI.create("http://127.0.0.1:" + server.app().port()
                    + "/repositories/export-match?" + query);
                var exported = client.send(java.net.http.HttpRequest.newBuilder(exportUri).GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
                assertEquals(exported.body(), 200, exported.statusCode());
                assertTrue(exported.body().contains("\"gdt_base64\""));
                for (String extra : List.of("&path=/other", "&version=1&version=2")) {
                    var rejected = client.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(uri + extra)).GET().build(),
                        java.net.http.HttpResponse.BodyHandlers.ofString());
                    assertEquals(rejected.body(), 400, rejected.statusCode());
                }
                assertEquals(2, fixture.readonlyOpens);
                assertEquals(0, fixture.forbiddenCalls);
            } finally { server.stop(); }
        } finally {
            if (previous == null) System.clearProperty(property);
            else System.setProperty(property, previous);
        }
    }

    @Test public void recursiveStructuredTypesRetainShapeWithoutRecursiveExpansion() throws Exception {
        try (Fixture fixture = new Fixture()) {
            GhidraSwing.runRead(() -> {
                int tx = fixture.program.startTransaction("structured signature fixture");
                try {
                    StructureDataType node = new StructureDataType("Node", 0);
                    node.add(new PointerDataType(node, 8), "next", null);
                    node.add(new ArrayDataType(IntegerDataType.dataType, 3, 4), "values", null);
                    EnumDataType state = new EnumDataType("State", 4);
                    state.add("READY", 7);
                    node.add(new TypedefDataType("StateAlias", state), "state", null);
                    UnionDataType payload = new UnionDataType("Payload");
                    payload.add(IntegerDataType.dataType, "number", null);
                    payload.add(new PointerDataType(CharDataType.dataType, 8), "text", null);
                    node.add(payload, "payload", null);
                    node.addBitField(IntegerDataType.dataType, 3, "flags", null);
                    FunctionDefinitionDataType callback = new FunctionDefinitionDataType("Callback");
                    callback.setReturnType(IntegerDataType.dataType);
                    callback.setArguments(new ParameterDefinitionImpl("value", IntegerDataType.dataType, null));
                    callback.setVarArgs(true);
                    node.add(new PointerDataType(callback, 8), "callback", null);
                    fixture.function.setReturnType(new PointerDataType(node, 8), SourceType.USER_DEFINED);
                } finally { fixture.program.endTransaction(tx, true); }
                return null;
            });
            Map<String, Object> snapshot = BSimFunctionSnapshot.capture(fixture.program, fixture.function, 1000);
            Map<?, ?> graph = (Map<?, ?>) snapshot.get("types");
            Set<Object> kinds = new java.util.HashSet<>();
            for (Object descriptor : graph.values()) kinds.add(((Map<?, ?>) descriptor).get("kind"));
            assertTrue(kinds.containsAll(Set.of("pointer", "struct", "array", "enum", "typedef", "union",
                "bitfield", "function_definition", "builtin")));
            assertEquals(true, snapshot.get("types_complete"));
            Map<?, ?> function = (Map<?, ?>) snapshot.get("function");
            Map<?, ?> rootPointer = (Map<?, ?>) graph.get(function.get("return_type"));
            Object nodeId = rootPointer.get("target");
            Map<?, ?> node = (Map<?, ?>) graph.get(nodeId);
            Map<?, ?> next = (Map<?, ?>) ((List<?>) node.get("components")).get(0);
            Map<?, ?> nextPointer = (Map<?, ?>) graph.get(next.get("type"));
            assertEquals(nodeId, nextPointer.get("target"));
        }
    }

    @Test public void typeDepthLimitsAreExplicitAndChangedSnapshotsAreRefused() throws Exception {
        try (Fixture fixture = new Fixture()) {
            GhidraSwing.runRead(() -> {
                int tx = fixture.program.startTransaction("bounded type fixture");
                try {
                    DataType deep = IntegerDataType.dataType;
                    for (int index = 0; index < 24; index++) deep = new PointerDataType(deep, 8);
                    fixture.function.setReturnType(deep, SourceType.USER_DEFINED);
                } finally { fixture.program.endTransaction(tx, true); }
                return null;
            });
            assertEquals(false, BSimFunctionSnapshot.capture(fixture.program, fixture.function, 1000).get("types_complete"));
            Function changing = proxy(Function.class, (p, method, args) -> {
                if (method.getName().equals("getPrototypeString")) {
                    assertTrue(SwingUtilities.isEventDispatchThread());
                    int tx = fixture.program.startTransaction("concurrent annotation fixture");
                    try { fixture.function.setComment("changed during snapshot"); }
                    finally { fixture.program.endTransaction(tx, true); }
                }
                return method.invoke(fixture.function, args);
            });
            expect("BSIM_SNAPSHOT_CHANGED", () -> BSimFunctionSnapshot.capture(fixture.program, changing, 1000));
            assertEquals(List.of(fixture.owner), fixture.program.getConsumerList());
            expect("BSIM_SNAPSHOT_THREAD", () -> GhidraSwing.runRead(
                () -> BSimFunctionSnapshot.capture(fixture.program, fixture.function, 1000)));
            expect("BSIM_SNAPSHOT_INVALID", () -> BSimFunctionSnapshot.capture(fixture.program, fixture.function, 0));
        }
    }

    @Test public void exactSpaceAndOffsetNeverSilentlySelectAnotherFunction() {
        AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        AddressSpace overlay = new GenericAddressSpace("overlay", 32, AddressSpace.TYPE_RAM, 1);
        AddressSpace second = new GenericAddressSpace("second", 32, AddressSpace.TYPE_RAM, 2);
        var factory = new DefaultAddressFactory(new AddressSpace[] { ram, overlay, second }, ram);
        Map<Address, Function> functions = new HashMap<>();
        Function a = namedFunction("old", ram.getAddress(0x1000));
        Function b = namedFunction("old", overlay.getAddress(0x1000));
        functions.put(a.getEntryPoint(), a);
        functions.put(b.getEntryPoint(), b);
        FunctionManager manager = proxy(FunctionManager.class, (p, m, args) ->
            m.getName().equals("getFunctionAt") ? functions.get(args[0]) : zero(m.getReturnType()));
        Program program = proxy(Program.class, (p, m, args) -> switch (m.getName()) {
            case "getAddressFactory" -> factory;
            case "getFunctionManager" -> manager;
            default -> zero(m.getReturnType());
        });
        expect("BSIM_REFERENCE_ADDRESS_AMBIGUOUS", () -> RepositoryService.resolveMatchFunction(program, "0x1000", "renamed"));
        expect("BSIM_REFERENCE_ADDRESS_AMBIGUOUS", () -> RepositoryService.resolveMatchFunction(program, "0x1000", "old"));
        Function selectedOverlay = namedFunction("library::selected", b.getEntryPoint());
        functions.put(b.getEntryPoint(), selectedOverlay);
        assertSame(selectedOverlay, RepositoryService.resolveMatchFunction(program, "0x1000", "library::selected"));
        assertSame(a, RepositoryService.resolveMatchFunction(program, "0x1000", "old"));
        functions.put(b.getEntryPoint(), b);
        assertSame(b, RepositoryService.resolveMatchFunction(program, "overlay::0x1000", "renamed"));
        expect("BSIM_REFERENCE_FUNCTION_NOT_FOUND", () -> RepositoryService.resolveMatchFunction(program, "overlay::0x1001", "old"));
        functions.remove(a.getEntryPoint());
        assertSame(b, RepositoryService.resolveMatchFunction(program, "0x1000", "old"));
        Function c = namedFunction("old", second.getAddress(0x1000));
        functions.put(c.getEntryPoint(), c);
        expect("BSIM_REFERENCE_ADDRESS_AMBIGUOUS", () -> RepositoryService.resolveMatchFunction(program, "0x1000", "old"));
    }

    private static Function namedFunction(String name, Address address) {
        return proxy(Function.class, (p, m, args) -> switch (m.getName()) {
            case "getName" -> name;
            case "getEntryPoint" -> address;
            default -> zero(m.getReturnType());
        });
    }

    private static void expect(String code, Runnable operation) {
        try { operation.run(); fail("Expected " + code); }
        catch (ConnectionException expected) { assertEquals(code, expected.code()); }
    }

    private static void expectRepository(String code, Runnable operation) {
        try { operation.run(); fail("Expected " + code); }
        catch (RepositoryService.RepositoryException expected) { assertEquals(code, expected.code()); }
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, handler);
    }

    private static Object zero(Class<?> type) {
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        return null;
    }
}
