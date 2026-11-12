package eu.starsong.ghidra.service;

import static org.junit.Assert.*;
import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.server.ManagedProgramGuard;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/** Real local native programs only: no repository writes, network or credential-store reads. */
public class BSimMatchApplicationTest {
    private static final String MD5 = "3533f690ac55480d83672c91b3762e36";
    private static final String URL = "ghidra://example.invalid/repository/program";
    private final Object owner = new Object();
    private ProgramDB reference, target;
    private Function source, destination;
    private BSimMatchService matches;
    private BSimMatchApplyService apply;
    private Path directory;
    private String oldDirectory;
    private String id;
    private Object managedOwner;

    @Before public void setup() throws Exception {
        oldDirectory = System.getProperty(ConnectionProfiles.PROPERTY);
        directory = Files.createTempDirectory("ghydra-native-apply-");
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        System.setProperty(ConnectionProfiles.PROPERTY, directory.toString());
        protectedFile(".lock", "");
        protectedFile("profiles.json", "{\"version\":1,\"profiles\":{\"a\":{\"kind\":\"bsim\",\"backend\":\"h2\",\"endpoint\":\"" + directory.resolve("a")
            + "\",\"auth\":\"none\",\"permissions\":[\"query\"]},\"b\":{\"kind\":\"bsim\",\"backend\":\"h2\",\"endpoint\":\"" + directory.resolve("b")
            + "\",\"auth\":\"none\",\"permissions\":[\"query\"]}}}");
        reference = program("native-reference", "x86:LE:64:default");
        target = program("native-target", "x86:LE:64:default");
        GhidraSwing.runRead(() -> {
            int tx = reference.startTransaction("Create exact recursive source signature");
            try {
                reference.setExecutableMD5(MD5);
                source = function(reference, "selected_reference", 0x2000);
                var library = reference.getSymbolTable().createNameSpace(reference.getGlobalNamespace(), "library", SourceType.USER_DEFINED);
                var inner = reference.getSymbolTable().createNameSpace(library, "inner", SourceType.USER_DEFINED);
                source.setParentNamespace(inner);
                var path = new CategoryPath("/native_apply");
                StructureDataType node = new StructureDataType(path, "Node", 0, reference.getDataTypeManager());
                node.add(new PointerDataType(node, 8, reference.getDataTypeManager()), "next", "Do not copy field comment");
                EnumDataType status = new EnumDataType(path, "Status", 4, reference.getDataTypeManager());
                status.add("READY", 1, "Do not copy enum comment"); status.add("BUSY", 2);
                UnionDataType payload = new UnionDataType(path, "Payload", reference.getDataTypeManager());
                payload.add(LongLongDataType.dataType, "number", null);
                payload.add(new PointerDataType(node, 8, reference.getDataTypeManager()), "node", null);
                node.add(payload, "payload", null);
                FunctionDefinitionDataType callback = new FunctionDefinitionDataType(path, "Callback", reference.getDataTypeManager());
                callback.setReturnType(status);
                callback.setArguments(new ParameterDefinitionImpl("node", new PointerDataType(node, 8, reference.getDataTypeManager()), "No parameter comments"));
                callback.setCallingConvention("__cdecl");
                node.add(new PointerDataType(callback, 8, reference.getDataTypeManager()), "callback", null);
                TypedefDataType alias = new TypedefDataType(path, "NodeAlias", node, reference.getDataTypeManager());
                source.updateFunction("__cdecl", new ReturnParameterImpl(status, reference), List.of(
                    new ParameterImpl("head", new PointerDataType(alias, 8, reference.getDataTypeManager()), reference),
                    new ParameterImpl("count", IntegerDataType.dataType, reference)),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.USER_DEFINED);
                source.setVarArgs(true);
                source.setComment("Do not copy function comment");
                source.getParameter(0).setComment("Do not copy parameter comment");
                reference.getDataTypeManager().resolve(new StructureDataType(path, "Unrelated", 100), DataTypeConflictHandler.DEFAULT_HANDLER);
            } finally { reference.endTransaction(tx, true); }
            tx = target.startTransaction("Create target annotation");
            try {
                destination = function(target, "original_target", 0x1000);
                destination.setComment("Retain target function comment");
            } finally { target.endTransaction(tx, true); }
            return null;
        });
        matches = new BSimMatchService(); apply = new BSimMatchApplyService(matches); id = select();
    }

    private void protectedFile(String name, String value) throws Exception {
        Path file = directory.resolve(name); Files.writeString(file, value);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    }
    private ProgramDB program(String name, String languageId) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        return new ProgramDB(name, language, language.getDefaultCompilerSpec(), owner);
    }
    private Function function(ProgramDB program, String name, long offset) throws Exception {
        var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        program.getMemory().createInitializedBlock("text", start, 16, (byte) 0, TaskMonitor.DUMMY, false);
        return program.getFunctionManager().createFunction(name, start, new AddressSet(start, start.add(15)), SourceType.USER_DEFINED);
    }
    private String select() {
        Map<String, Object> match = new LinkedHashMap<>(Map.of("function", "indexed_original", "address", "ram::0x2000",
            "executable_md5", MD5, "repository_url", URL));
        var rows = new ArrayList<Map<String, Object>>();
        rows.add(new LinkedHashMap<>(Map.of("function", "wrong_best_match", "address", "ram::0x3333",
            "executable_md5", MD5, "repository_url", URL, "similarity", 1.0)));
        rows.add(match); // Apply the explicitly selected second row, never silently query/choose the best.
        Map<String, Object> query = new LinkedHashMap<>(Map.of("success", true, "matches", rows,
            "source_address", BSimMatchService.qualifiedAddress(destination), "source_modification", target.getModificationNumber()));
        matches.register(target, query);
        return (String) match.get("match_id");
    }
    private Map<String, Object> export(String matchId) {
        Map<String, Object> result = new LinkedHashMap<>(BSimSignatureTransfer.export(reference, source));
        result.put("match_id", matchId); result.put("identity_verified", true);
        result.put("profile", "approved-reference"); result.put("path", "/program"); result.put("version", 7);
        result.put("identity", Map.of("repository_url", URL, "executable_md5", MD5,
            "address", "ram::0x2000", "selected_address", "ram::0x2000", "indexed_function", "indexed_original"));
        return result;
    }
    private String prepare() { return (String) apply.prepare(target, id, export(id)).get("apply_token"); }
    private static void failure(String code, Runnable operation) {
        try { operation.run(); fail("Expected native refusal " + code); }
        catch (ConnectionException e) { assertEquals(e.getMessage(), code, e.code()); }
    }
    @After public void cleanup() throws Exception {
        if (target != null && !target.isClosed()) target.release(owner);
        if (managedOwner != null && target != null && !target.isClosed()) target.release(managedOwner);
        if (reference != null && !reference.isClosed()) reference.release(owner);
        if (oldDirectory == null) System.clearProperty(ConnectionProfiles.PROPERTY); else System.setProperty(ConnectionProfiles.PROPERTY, oldDirectory);
        if (directory != null) try (var files = Files.walk(directory)) {
            for (Path file : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(file);
        }
    }

    @Test public void preparationIsReadonlyAndExplicitApplyImportsCompleteRecursiveNativeTypes() {
        long stamp = target.getModificationNumber(), referenceStamp = reference.getModificationNumber();
        Map<String, Object> prepared = apply.prepare(target, id, export(id));
        assertEquals(false, prepared.get("applied"));
        assertEquals(stamp, target.getModificationNumber());
        assertNull(target.getDataTypeManager().getDataType("/native_apply/Node"));
        assertEquals("original_target", destination.getName());
        Map<?, ?> preview = (Map<?, ?>) prepared.get("preview");
        assertEquals(false, preview.get("comments_transferred"));
        assertTrue(((List<?>) preview.get("types")).size() > 6);
        Map<String, Object> applied = apply.apply(target, id, (String) prepared.get("apply_token"));
        assertEquals(true, applied.get("applied"));
        assertEquals(preview, applied.get("summary"));
        assertEquals("library::inner::selected_reference", destination.getName(true));
        assertEquals("__cdecl", destination.getCallingConventionName());
        assertTrue(destination.hasVarArgs()); assertEquals(2, destination.getParameterCount());
        assertEquals("head", destination.getParameter(0).getName()); assertEquals("count", destination.getParameter(1).getName());
        assertEquals("/native_apply/Status", destination.getReturnType().getPathName());
        assertEquals("Retain target function comment", destination.getComment());
        assertNull(destination.getParameter(0).getComment());
        Structure node = (Structure) target.getDataTypeManager().getDataType("/native_apply/Node");
        Pointer next = (Pointer) node.getComponent(0).getDataType();
        assertEquals(8, next.getLength()); assertSame(node, next.getDataType());
        assertNull(node.getComponent(0).getComment());
        assertTrue(target.getDataTypeManager().getDataType("/native_apply/Payload") instanceof Union);
        assertTrue(target.getDataTypeManager().getDataType("/native_apply/NodeAlias") instanceof TypeDef);
        FunctionDefinition callback = (FunctionDefinition) target.getDataTypeManager().getDataType("/native_apply/Callback");
        assertEquals("node", callback.getArguments()[0].getName());
        assertEquals(2, ((ghidra.program.model.data.Enum) destination.getReturnType()).getValue("BUSY"));
        assertNull(target.getDataTypeManager().getDataType("/native_apply/Unrelated"));
        assertEquals(referenceStamp, reference.getModificationNumber());
        failure("BSIM_APPLY_TOKEN", () -> apply.apply(target, id, (String) prepared.get("apply_token")));
    }

    @Test public void incompatibleLayoutAndAnnotationCollisionsAreRejectedWithoutMutation() {
        GhidraSwing.runRead(() -> {
            int tx = target.startTransaction("Create conflicting type");
            try {
                StructureDataType conflict = new StructureDataType(new CategoryPath("/native_apply"), "Node", 0);
                conflict.add(IntegerDataType.dataType, "different_name", null);
                target.getDataTypeManager().resolve(conflict, DataTypeConflictHandler.DEFAULT_HANDLER);
            } finally { target.endTransaction(tx, true); }
        });
        id = select(); long stamp = target.getModificationNumber();
        failure("BSIM_SIGNATURE_TYPE_CONFLICT", () -> apply.prepare(target, id, export(id)));
        assertEquals(stamp, target.getModificationNumber()); assertEquals("original_target", destination.getName());
        assertNull(target.getSymbolTable().getNamespace("library", target.getGlobalNamespace()));
    }

    @Test public void changedTargetDifferentProgramUnknownAndWrongTokensAreRefused() throws Exception {
        String token = prepare();
        failure("BSIM_APPLY_TOKEN", () -> apply.apply(target, id, "unknown"));
        failure("BSIM_APPLY_TOKEN", () -> apply.apply(target, UUID.randomUUID().toString(), token));
        failure("BSIM_APPLY_TOKEN", () -> apply.apply(target, id, token));
        final String stale = prepare();
        GhidraSwing.runRead(() -> {
            int tx = target.startTransaction("Change target after preview");
            try { destination.setComment("Target changed"); } finally { target.endTransaction(tx, true); }
        });
        failure("BSIM_MATCH_STALE", () -> apply.apply(target, id, stale));
        id = select(); final String wrongProgram = prepare();
        failure("BSIM_MATCH_STALE", () -> apply.apply(reference, id, wrongProgram));
        assertEquals("original_target", destination.getName());
    }

    @Test public void referenceIdentityDigestAndAbiCannotBeSubstituted() {
        Map<String, Object> result = export(id);
        result.put("match_id", UUID.randomUUID().toString());
        failure("BSIM_SIGNATURE_INVALID", () -> apply.prepare(target, id, result));
        result.put("match_id", id);
        Map<String, Object> identity = new LinkedHashMap<>((Map<String, Object>) result.get("identity"));
        identity.put("selected_address", "ram::0x2001"); result.put("identity", identity);
        failure("BSIM_SIGNATURE_INVALID", () -> apply.prepare(target, id, result));
        result.put("identity", export(id).get("identity"));
        result.put("abi", Map.of("language", "x86:LE:32:default", "compiler", "default", "pointer_size", 4));
        failure("BSIM_SIGNATURE_ABI", () -> apply.prepare(target, id, result));
        result.put("abi", BSimSignatureTransfer.abi(reference));
        Map<String, Object> archive = new LinkedHashMap<>((Map<String, Object>) result.get("archive"));
        archive.put("sha256", "0".repeat(64)); result.put("archive", archive);
        failure("BSIM_SIGNATURE_INVALID", () -> apply.prepare(target, id, result));
        archive.put("gdt_base64", "A".repeat(699056));
        failure("BSIM_SIGNATURE_TOO_LARGE", () -> apply.prepare(target, id, result));
    }

    @Test public void managedReadonlyNeverAppliesEvenWhenNativeViewIsChangeable() throws Exception {
        String token = prepare();
        Class<?> activeClass = Class.forName("eu.starsong.ghidra.server.ActiveProgram");
        var constructor = activeClass.getDeclaredConstructor(Program.class, ghidra.framework.model.Project.class);
        constructor.setAccessible(true);
        managedOwner = constructor.newInstance(target, null);
        target.addConsumer(managedOwner);
        ManagedProgramGuard.registerReadOnly(target);
        failure("REPOSITORY_READ_ONLY", () -> apply.apply(target, id, token));
        assertEquals("original_target", destination.getName());
        assertNull(target.getDataTypeManager().getDataType("/native_apply/Node"));
    }

    @Test public void transactionCollisionRollsBackNamesNamespacesAndImportedDependencies() {
        // Same parameter name as an existing local makes the native update fail after namespace creation.
        GhidraSwing.runRead(() -> {
            int tx = target.startTransaction("Create local collision");
            try { destination.addLocalVariable(new LocalVariableImpl("head", IntegerDataType.dataType, -16, target), SourceType.USER_DEFINED); }
            finally { target.endTransaction(tx, true); }
            return null;
        });
        id = select(); String token = prepare();
        int types = target.getDataTypeManager().getDataTypeCount(true);
        Map<String, Object> before = BSimSignatureTransfer.annotation(destination);
        try { apply.apply(target, id, token); fail("Native duplicate local/parameter name must abort the complete transaction"); }
        catch (RuntimeException expected) { /* Native invalid input is translated by TransactionHelper. */ }
        GhidraSwing.runRead(() -> {
            assertEquals(before, BSimSignatureTransfer.annotation(destination));
            assertEquals(types, target.getDataTypeManager().getDataTypeCount(true));
            assertNull(target.getDataTypeManager().getDataType("/native_apply/Node"));
            assertNull(target.getSymbolTable().getNamespace("library", target.getGlobalNamespace()));
            assertEquals("head", destination.getLocalVariables()[0].getName());
        });
        failure("BSIM_APPLY_TOKEN", () -> apply.apply(target, id, token));
    }

    @Test public void wrongProfileAndEvictedTokensAreRefused() {
        String[] scoped = new String[2];
        ConnectionProfiles.withProfile("a", "bsim", "query", profile -> {
            id = select(); scoped[0] = id; scoped[1] = prepare(); return null;
        });
        ConnectionProfiles.withProfile("b", "bsim", "query", profile -> {
            failure("BSIM_MATCH_PROFILE", () -> apply.apply(target, scoped[0], scoped[1])); return null;
        });
        id = select(); Map<String, Object> exported = export(id);
        String old = (String) apply.prepare(target, id, exported).get("apply_token");
        for (int i = 0; i < 32; i++) apply.prepare(target, id, exported);
        failure("BSIM_APPLY_TOKEN", () -> apply.apply(target, id, old));
    }

    @Test public void existingUnrelatedOuterTransactionIsRefusedWithoutEndingIt() {
        String token = prepare();
        GhidraSwing.runRead(() -> {
            int tx = target.startTransaction("Outer caller transaction");
            try {
                var outer = target.getCurrentTransactionInfo();
                failure("BSIM_APPLY_BUSY", () -> apply.apply(target, id, token));
                assertSame(outer, target.getCurrentTransactionInfo());
            }
            finally { target.endTransaction(tx, false); }
        });
        assertEquals("original_target", destination.getName());
        assertNull(target.getDataTypeManager().getDataType("/native_apply/Node"));
    }

    @Test public void nativeCustomRegisterAndStackStorageAreTransferredExactly() {
        GhidraSwing.runRead(() -> {
            int tx = reference.startTransaction("Custom register and stack ABI");
            try {
                source.updateFunction(Function.UNKNOWN_CALLING_CONVENTION_STRING,
                    new ReturnParameterImpl(LongLongDataType.dataType, reference.getRegister("RAX"), reference),
                    List.of(new ParameterImpl("register_argument", LongLongDataType.dataType, reference.getRegister("RDI"), reference),
                        new ParameterImpl("stack_argument", IntegerDataType.dataType, 24, reference)),
                    Function.FunctionUpdateType.CUSTOM_STORAGE, false, SourceType.USER_DEFINED);
                source.setVarArgs(false);
            } finally { reference.endTransaction(tx, true); }
            return null;
        });
        Map<String, Object> expected = BSimSignatureTransfer.annotation(source);
        String token = prepare();
        assertEquals(true, apply.apply(target, id, token).get("applied"));
        assertTrue(destination.hasCustomVariableStorage());
        assertEquals(expected, BSimSignatureTransfer.annotation(destination));
        assertEquals(reference.getRegister("RDI"), destination.getParameter(0).getVariableStorage().getRegister());
        assertEquals(24, destination.getParameter(1).getStackOffset());
    }

    @Test public void sameAbiStructureReturnAutoParametersAreRegeneratedNotDuplicated() {
        GhidraSwing.runRead(() -> {
            int tx = reference.startTransaction("Native hidden structure return");
            try {
                StructureDataType result = new StructureDataType(new CategoryPath("/native_apply"), "LargeResult", 40, reference.getDataTypeManager());
                source.updateFunction("__cdecl", new ReturnParameterImpl(result, reference),
                    List.of(new ParameterImpl("count", IntegerDataType.dataType, reference)),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED);
                source.setVarArgs(false);
            } finally { reference.endTransaction(tx, true); }
            return null;
        });
        assertTrue("Fixture must exercise native hidden return-pointer ABI", source.getAutoParameterCount() > 0);
        Map<String, Object> expected = BSimSignatureTransfer.annotation(source);
        String token = prepare(); apply.apply(target, id, token);
        assertEquals(expected, BSimSignatureTransfer.annotation(destination));
        assertEquals(source.getParameterCount(), destination.getParameterCount());
        assertEquals(source.getAutoParameterCount(), destination.getAutoParameterCount());
    }

    @Test public void classNamespaceAndImplicitThisTypeArePreserved() {
        GhidraSwing.runRead(() -> {
            int tx = reference.startTransaction("Native class member ABI");
            try {
                var memberClass = reference.getSymbolTable().createClass(source.getParentNamespace(), "Widget", SourceType.USER_DEFINED);
                source.setParentNamespace(memberClass);
                source.updateFunction("__thiscall", new ReturnParameterImpl(IntegerDataType.dataType, reference),
                    List.of(new ParameterImpl("count", IntegerDataType.dataType, reference)),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED);
                source.setVarArgs(false);
            } finally { reference.endTransaction(tx, true); }
            return null;
        });
        assertTrue("Fixture must exercise implicit this", source.getAutoParameterCount() > 0);
        Map<String, Object> expected = BSimSignatureTransfer.annotation(source);
        String token = prepare(); apply.apply(target, id, token);
        assertTrue(destination.getParentNamespace() instanceof GhidraClass);
        assertEquals(expected, BSimSignatureTransfer.annotation(destination));
        assertEquals(source.getParameterCount(), destination.getParameterCount());
    }

    @Test public void headlessScriptReleasesOnlyItsOwnTransactionBeforeServing() throws Exception {
        String token = prepare();
        ghidra.app.script.GhidraScript servingScript = new ghidra.app.script.GhidraScript() {
            public void run() {
                assertNotNull(currentProgram.getCurrentTransactionInfo());
                end(true); // Same owned FlatProgramAPI lifecycle used by GhidraHeadlessServer.
                assertNull(currentProgram.getCurrentTransactionInfo());
                assertEquals(true, apply.apply(target, id, token).get("applied"));
                assertNull(currentProgram.getCurrentTransactionInfo());
            }
        };
        var state = new ghidra.app.script.GhidraState(null, null, target, null, null, null);
        servingScript.execute(state, TaskMonitor.DUMMY, new java.io.PrintWriter(java.io.OutputStream.nullOutputStream()));
        assertEquals("selected_reference", destination.getName());
        assertNull(target.getCurrentTransactionInfo());
    }

    @Test public void sameLayoutChangedMemberNamesAreNotSilentlyReusedViaSourceIds() {
        apply.apply(target, id, prepare());
        GhidraSwing.runRead(() -> {
            int tx = target.startTransaction("Preserve locally edited member annotation");
            try {
                Structure node = (Structure) target.getDataTypeManager().getDataType("/native_apply/Node");
                node.getComponent(0).setFieldName("locally_renamed");
            } finally { target.endTransaction(tx, true); }
            return null;
        });
        id = select(); long stamp = target.getModificationNumber();
        failure("BSIM_SIGNATURE_TYPE_CONFLICT", () -> apply.prepare(target, id, export(id)));
        assertEquals(stamp, target.getModificationNumber());
        Structure node = (Structure) target.getDataTypeManager().getDataType("/native_apply/Node");
        assertEquals("locally_renamed", node.getComponent(0).getFieldName());
    }

    @Test public void nativeHttpSelectionPreparationAndApplicationAreSeparateStrictOperations() throws Exception {
        String readonly = System.getProperty(eu.starsong.ghidra.middleware.ReadOnlyGuard.PROPERTY);
        System.setProperty(eu.starsong.ghidra.middleware.ReadOnlyGuard.PROPERTY, "false");
        var resource = new eu.starsong.ghidra.resource.BSimResource();
        var registry = resource.getClass().getDeclaredField("matches"); registry.setAccessible(true);
        matches = (BSimMatchService) registry.get(resource);
        id = ConnectionProfiles.withProfile("a", "bsim", "query", profile -> select());
        var server = new eu.starsong.ghidra.server.GhydraServer(null, 0, new HashMap<>(), false, target, null);
        server.register(resource); server.start();
        try {
            var client = java.net.http.HttpClient.newHttpClient();
            String base = "http://127.0.0.1:" + server.app().port() + "/bsim/matches/" + id;
            var selection = client.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(base + "/selection?profile=a")).GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(selection.body(), 200, selection.statusCode());
            assertFalse(selection.body().contains("\"decompilation\""));
            String body = new com.google.gson.Gson().toJson(Map.of("reference", export(id)));
            long stamp = target.getModificationNumber();
            var request = java.net.http.HttpRequest.newBuilder(java.net.URI.create(base + "/prepare-apply?profile=a"))
                .header("Content-Type", "application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build();
            var prepared = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(prepared.body(), 200, prepared.statusCode());
            assertEquals(stamp, target.getModificationNumber());
            var json = com.google.gson.JsonParser.parseString(prepared.body()).getAsJsonObject().getAsJsonObject("result");
            String token = json.get("apply_token").getAsString();
            assertFalse(json.get("applied").getAsBoolean());
            assertEquals("original_target", destination.getName());
            var invalid = client.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(base + "/apply?profile=a&apply_token=" + token))
                .header("Content-Type", "application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofString("{}")).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(invalid.body(), 400, invalid.statusCode());
            var applied = client.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(base + "/apply?profile=a"))
                .header("Content-Type", "application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                    new com.google.gson.Gson().toJson(Map.of("apply_token", token)))).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(applied.body(), 200, applied.statusCode());
            assertTrue(com.google.gson.JsonParser.parseString(applied.body()).getAsJsonObject().getAsJsonObject("result").get("applied").getAsBoolean());
            assertEquals("library::inner::selected_reference", destination.getName(true));
        } finally {
            server.stop();
            if (readonly == null) System.clearProperty(eu.starsong.ghidra.middleware.ReadOnlyGuard.PROPERTY);
            else System.setProperty(eu.starsong.ghidra.middleware.ReadOnlyGuard.PROPERTY, readonly);
        }
    }

    @Test public void activeTargetSwitchDuringDispatchRefusesThePreparedToken() {
        String token = prepare();
        failure("BSIM_MATCH_STALE", () -> apply.apply(target, id, token, () -> reference));
        assertEquals("original_target", destination.getName());
        assertNull(target.getDataTypeManager().getDataType("/native_apply/Node"));
    }

    @Test public void expiredTokensCannotBeAppliedAndConcurrentConsumersHaveOneWinner() throws Exception {
        var clock = new java.util.concurrent.atomic.AtomicLong();
        apply = new BSimMatchApplyService(matches, clock::get);
        String expired = prepare();
        clock.addAndGet(java.util.concurrent.TimeUnit.MINUTES.toNanos(5) + 1);
        failure("BSIM_APPLY_TOKEN", () -> apply.apply(target, id, expired));
        String token = prepare();
        var start = new java.util.concurrent.CountDownLatch(1);
        var executor = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            java.util.concurrent.Callable<String> consume = () -> {
                start.await();
                try { apply.apply(target, id, token); return "applied"; }
                catch (ConnectionException failure) { return failure.code(); }
            };
            var first = executor.submit(consume); var second = executor.submit(consume); start.countDown();
            var results = List.of(first.get(30, java.util.concurrent.TimeUnit.SECONDS), second.get(30, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(1, Collections.frequency(results, "applied"));
            assertEquals(1, Collections.frequency(results, "BSIM_APPLY_TOKEN"));
        } finally { executor.shutdownNow(); }
    }

    @Test public void nestedTypedefDependenciesRetainEveryAlias() throws Exception {
        GhidraSwing.runRead(() -> {
            int tx = reference.startTransaction("Nested typedef signature");
            try {
                var category = new CategoryPath("/aliases");
                var inner = new TypedefDataType(category, "Inner", IntegerDataType.dataType);
                var outer = new TypedefDataType(category, "Outer", inner);
                source.getParameter(0).setDataType(new PointerDataType(outer, 8), SourceType.USER_DEFINED);
            } finally { reference.endTransaction(tx, true); }
            return null;
        });
        String token = prepare();
        apply.apply(target, id, token);
        GhidraSwing.runRead(() -> {
            var outer = (TypeDef) target.getDataTypeManager().getDataType("/aliases/Outer");
            assertTrue(outer.getDataType() instanceof TypeDef);
            assertEquals("/aliases/Inner", outer.getDataType().getPathName());
            assertTrue(((TypeDef) outer.getDataType()).getDataType().isEquivalent(IntegerDataType.dataType));
        });
    }

    @Test public void nativeBitfieldComponentsRetainTheirLayout() throws Exception {
        GhidraSwing.runRead(() -> {
            int tx = reference.startTransaction("Bitfield signature dependency");
            try {
                var flags = new StructureDataType("Flags", 0);
                flags.addBitField(IntegerDataType.dataType, 3, "mode", null);
                flags.addBitField(IntegerDataType.dataType, 5, "state", null);
                source.getParameter(0).setDataType(new PointerDataType(flags, 8), SourceType.USER_DEFINED);
            } finally { reference.endTransaction(tx, true); }
            return null;
        });
        String token = prepare();
        apply.apply(target, id, token);
        GhidraSwing.runRead(() -> {
            var flags = (Structure) target.getDataTypeManager().getDataType("/Flags");
            assertEquals(2, flags.getNumDefinedComponents());
            assertEquals("mode", flags.getComponent(0).getFieldName());
            assertEquals(3, ((BitFieldDataType) flags.getComponent(0).getDataType()).getDeclaredBitSize());
            assertEquals(5, ((BitFieldDataType) flags.getComponent(1).getDataType()).getDeclaredBitSize());
        });
    }
}
