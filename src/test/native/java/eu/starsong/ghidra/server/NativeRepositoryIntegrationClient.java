package eu.starsong.ghidra.server;

import static org.junit.Assert.*;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.connection.WorkerTLS;
import eu.starsong.ghidra.service.RepositoryService;
import eu.starsong.ghidra.service.SaveService;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.DBStringMapAdapter;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageVersionException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.server.ServerAdmin;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;

/** Child-only entry point: native RMI's cached TLS factory cannot share the suite JVM. */
public final class NativeRepositoryIntegrationClient {
    private static final String PROFILE = "native-fixture";
    private static final String ORIGINAL_FUNCTION = "fixture_function";
    private static final String CHANGED_FUNCTION = "persisted_fixture_function";
    private static final String COMPATIBILITY_PROGRAM = "compatibility-program";
    private static final String SEED_COMMENT = "Synthetic native fixture seed";
    private static final String CHECKIN_COMMENT = "Persist synthetic function and memory";
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;

    private NativeRepositoryIntegrationClient() {}

    public static void main(String[] arguments) {
        int result = 1;
        try {
            assertTrue("Expected fixture mode and Ghidra home", arguments.length >= 3);
            System.setProperty("ghidra.mcp.bind.host", "127.0.0.1");
            if ("workflow".equals(arguments[0])) {
                assertNotNull("Fixture profile store must be supplied before initialization",
                    System.getProperty(ConnectionProfiles.PROPERTY));
                assertNotNull("Fixture public CA must be supplied before initialization",
                    System.getProperty("ghidra.cacerts"));
                WorkerTLS.initialize();
            }
            Application.initializeApplication(new GhidraApplicationLayout(new File(arguments[1])),
                new HeadlessGhidraApplicationConfiguration());
            if ("admin".equals(arguments[0])) {
                new ServerAdmin().execute(new String[] { arguments[2], "-add", "fixture_user" });
            } else {
                assertEquals("workflow", arguments[0]);
                assertEquals(4, arguments.length);
                assertTrue("Native TLS initialization replaced the verified worker provider",
                    SSLContext.getDefault().getProvider().getClass().getName()
                        .startsWith("eu.starsong.ghidra.connection.WorkerTLS"));
                Path root = Path.of(arguments[2]);
                int instance = Integer.parseInt(arguments[3]);
                seed(root);
                exerciseConnector(root, instance);
                System.out.println("NATIVE_REPOSITORY_INTEGRATION_PASSED");
            }
            result = 0;
        } catch (Throwable failure) {
            failure.printStackTrace(System.err);
        } finally {
            // Ghidra's native RMI/DB/Swing threads otherwise outlive even a completed verdict.
            System.exit(result);
        }
    }

    private static void seed(Path root) {
        // withProfile installs WorkerAuthentication only for this native callback.
        ConnectionProfiles.withProfile(PROFILE, "ghidra", "checkout", profile -> {
            try {
                URI endpoint = URI.create(profile.endpoint());
                var server = ClientUtil.getRepositoryServer(endpoint.getHost(), endpoint.getPort(), true);
                assertTrue("Synthetic server authentication failed", server.connect());
                assertEquals("fixture_user", server.getUser());
                var repository = server.createRepository("corpus");
                repository.connect();
                Path seedDirectory = root.resolve("seed");
                Files.createDirectory(seedDirectory,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                GhidraProject project = GhidraProject.createProject(seedDirectory.toString(), "seed", false);
                try {
                    project.getProjectData().convertProjectToShared(repository, MONITOR);
                } finally {
                    project.close();
                }
                // Native conversion replaces its filesystem without clearing existing folder caches.
                // Seed through a reopened project, never through the disposed private filesystem.
                project = GhidraProject.openProject(seedDirectory.toString(), "seed", false);
                try {
                    var language = DefaultLanguageService.getLanguageService()
                        .getLanguage(new LanguageID("x86:LE:64:default"));
                    assertTrue("Fixture requires a preceding minor language version",
                        language.getMinorVersion() > 0);
                    for (String name : List.of("program", COMPATIBILITY_PROGRAM)) {
                        Object owner = new Object();
                        ProgramDB program = new ProgramDB(name, language,
                            language.getDefaultCompilerSpec(), owner);
                        DomainFile file;
                        try {
                            int transaction = program.startTransaction("Seed synthetic native program");
                            boolean commit = false;
                            try {
                                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                                program.getMemory().createInitializedBlock("text", start, 16, (byte) 0,
                                    MONITOR, false);
                                program.getFunctionManager().createFunction(ORIGINAL_FUNCTION, start,
                                    new AddressSet(start, start.add(15)), SourceType.USER_DEFINED);
                                if (name.equals(COMPATIBILITY_PROGRAM)) {
                                    // ProgramDB's installed SDK source defines this map/key. Change
                                    // only the owned synthetic database, never language files or a server fixture.
                                    var metadata = new DBStringMapAdapter(program.getDBHandle(), "Program", false);
                                    assertEquals(language.getVersion() + "." + language.getMinorVersion(),
                                        metadata.get("Language Version"));
                                    metadata.put("Language Version",
                                        language.getVersion() + "." + (language.getMinorVersion() - 1));
                                }
                                commit = true;
                            } finally {
                                program.endTransaction(transaction, commit);
                            }
                            file = project.getProjectData().getRootFolder().createFile(name, program, MONITOR);
                        } finally {
                            program.release(owner);
                        }
                        file.addToVersionControl(SEED_COMMENT, false, MONITOR);
                        assertTrue(file.isVersioned());
                        assertEquals(1, file.getLatestVersion());
                        assertFalse("Seed must not own a checkout", file.isCheckedOut());
                        if (name.equals(COMPATIBILITY_PROGRAM)) assertSourceNeedsMinorCompatibility(file);
                    }
                } finally {
                    project.close();
                }
                System.out.println("NATIVE_REPOSITORY_SEEDED");
                return null;
            } catch (Exception failure) {
                throw new AssertionError("Could not seed owned synthetic native repository", failure);
            }
        });
    }

    private static void exerciseConnector(Path root, int instance) throws Exception {
        Path checkout = root.resolve("store/repositories/instance-" + instance + "/" + PROFILE);
        assertFalse("Regression must begin with a never-converted independent workspace",
            Files.exists(checkout));

        Program compatibility;
        try (RepositoryService service = new RepositoryService(instance);
             ActiveProgram selection = new ActiveProgram(null, null)) {
            GhidraContext context = context(instance, selection);
            // This is deliberately the first operation: the old connector exposed the converted
            // workspace's disposed filesystem and listed no program (or failed during refresh).
            var entry = programEntry(service.files(PROFILE, "/", 0, 100), "program");
            assertEquals(1, number(entry, "latest_version"));
            assertFalse((boolean) entry.get("checked_out"));
            assertTrue(Files.isRegularFile(checkout.resolve("checkout.gpr")));
            var status = service.status(PROFILE);
            assertEquals(PROFILE, status.get("profile"));
            assertEquals(true, status.get("connected"));
            assertEquals(false, status.get("read_only"));
            assertEquals(java.util.Set.of("read", "checkout", "checkin"), status.get("permissions"));

            var opened = service.open(context, PROFILE, "/" + COMPATIBILITY_PROGRAM, 1);
            assertEquals(true, opened.get("opened"));
            assertEquals(true, opened.get("read_only"));
            assertEquals(1, number(opened, "version"));
            compatibility = context.requireProgram();
            assertTrue(context.hasRepositorySelection());
            assertTrue(ManagedProgramGuard.isManaged(compatibility));
            DomainFile source = context.project().getProjectData().getRootFolder()
                .getFile(COMPATIBILITY_PROGRAM);
            assertNotNull(source);
            assertSourceNeedsMinorCompatibility(source);
            assertTrue(compatibility.getDomainFile().isReadOnly());
            assertEquals(1, compatibility.getDomainFile().getVersion());
            assertEquals("/" + COMPATIBILITY_PROGRAM, compatibility.getDomainFile().getPathname());
            assertFalse("Compatibility opening must not create local unsaved changes", compatibility.isChanged());
            assertContents(compatibility, ORIGINAL_FUNCTION, (byte) 0);
            int consumers = compatibility.getConsumerList().size();
            assertTrue(compatibility.isUsedBy(service));
            assertTrue(compatibility.isUsedBy(selection));
            service.open(context, PROFILE, "/" + COMPATIBILITY_PROGRAM, 1);
            assertSame(compatibility, context.requireProgram());
            service.open(context, PROFILE, "/" + COMPATIBILITY_PROGRAM, -1);
            assertSame(compatibility, context.requireProgram());
            assertEquals("Repeated opens must not leak or release native consumers", consumers,
                compatibility.getConsumerList().size());
            try {
                TransactionHelper.executeInTransaction(compatibility, "Denied compatibility mutation", () -> {
                    var start = compatibility.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                    compatibility.getFunctionManager().getFunctionAt(start).setName("forbidden", SourceType.USER_DEFINED);
                    compatibility.getMemory().setByte(start, (byte) 0x7f);
                    return null;
                });
                fail("Managed readonly compatibility views must reject mutation");
            } catch (ConnectionException denied) {
                assertEquals("REPOSITORY_READ_ONLY", denied.code());
                assertEquals(403, denied.status());
            }
            assertFalse("No-change readonly saves must remain harmless", new SaveService().save(compatibility).saved());
            assertFalse(compatibility.isChanged());
            assertContents(compatibility, ORIGINAL_FUNCTION, (byte) 0);
            var compatibilityEntry = programEntry(service.files(PROFILE, "/", 0, 100), COMPATIBILITY_PROGRAM);
            assertEquals(1, number(compatibilityEntry, "latest_version"));
            assertEquals(false, compatibilityEntry.get("checked_out"));
            assertEquals(false, compatibilityEntry.get("modified_since_checkout"));
            assertSourceNeedsMinorCompatibility(source);
            assertSeedOnlyHistory(source);
        }
        assertTrue("Both real headless and service consumers must release the compatibility program",
            compatibility.isClosed());

        Program writable;
        // A new service reopens the existing independent workspace rather than reconverting it.
        try (RepositoryService service = new RepositoryService(instance);
             ActiveProgram selection = new ActiveProgram(null, null)) {
            GhidraContext context = context(instance, selection);
            var checkedOut = service.checkout(PROFILE, "/program", true);
            assertEquals(true, checkedOut.get("checked_out"));
            assertEquals(true, checkedOut.get("exclusive"));
            assertEquals(1, number(checkedOut, "latest_version"));
            var opened = service.open(context, PROFILE, "/program", -1);
            assertEquals(false, opened.get("read_only"));
            writable = context.requireProgram();
            assertTrue(writable.isChangeable());
            assertTrue(ManagedProgramGuard.isManaged(writable));
            assertTrue(writable.getDomainFile().isCheckedOutExclusive());
            assertContents(writable, ORIGINAL_FUNCTION, (byte) 0);

            TransactionHelper.executeInTransaction(writable, "Persist synthetic repository mutation", () -> {
                var start = writable.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                writable.getFunctionManager().getFunctionAt(start).setName(CHANGED_FUNCTION, SourceType.USER_DEFINED);
                writable.getMemory().setByte(start, (byte) 0x5a);
                return null;
            });
            assertTrue(writable.isChanged());
            SaveService.SaveResult saved = new SaveService().save(writable);
            assertTrue("SaveService must persist the real checked-out ProgramDB", saved.saved());
            assertFalse(writable.isChanged());
            var savedEntry = programEntry(service.files(PROFILE, "/", 0, 100), "program");
            assertEquals("Local save must not masquerade as repository check-in", 1,
                number(savedEntry, "latest_version"));
            assertEquals(true, savedEntry.get("modified_since_checkout"));

            var checkedIn = service.checkin(PROFILE, "/program", CHECKIN_COMMENT, true);
            assertEquals(true, checkedIn.get("checked_in"));
            assertEquals(2, number(checkedIn, "latest_version"));
            assertEquals(2, number(checkedIn, "version"));
            assertEquals(true, checkedIn.get("checked_out"));
            assertEquals(true, checkedIn.get("exclusive"));
            assertEquals(false, checkedIn.get("modified_since_checkout"));
            assertFalse(writable.isChanged());
        }
        assertTrue("Writable program must close before native workspace reopen", writable.isClosed());

        // Persisted checkout metadata must survive a real native project close/open cycle.
        try (RepositoryService service = new RepositoryService(instance);
             ActiveProgram selection = new ActiveProgram(null, null)) {
            var entry = programEntry(service.files(PROFILE, "/", 0, 100), "program");
            assertEquals(2, number(entry, "latest_version"));
            assertEquals(true, entry.get("checked_out"));
            assertEquals(true, entry.get("exclusive"));
            GhidraContext context = context(instance, selection);
            assertEquals(false, service.open(context, PROFILE, "/program", -1).get("read_only"));
            assertContents(context.requireProgram(), CHANGED_FUNCTION, (byte) 0x5a);
        }

        // A second, never-converted workspace proves persistence in the server, not an in-memory
        // ProgramDB or the original checkout's local save/cache. Version 1 remains unchanged.
        try (RepositoryService service = new RepositoryService(instance + 1);
             ActiveProgram selection = new ActiveProgram(null, null)) {
            GhidraContext context = context(instance + 1, selection);
            var entry = programEntry(service.files(PROFILE, "/", 0, 100), "program");
            assertEquals(2, number(entry, "latest_version"));
            assertEquals(false, entry.get("checked_out"));
            var latest = service.open(context, PROFILE, "/program", -1);
            assertEquals(true, latest.get("read_only"));
            assertEquals(2, number(latest, "version"));
            assertContents(context.requireProgram(), CHANGED_FUNCTION, (byte) 0x5a);
            assertHistory(context.project().getProjectData().getRootFolder().getFile("program"));
            var original = service.open(context, PROFILE, "/program", 1);
            assertEquals(true, original.get("read_only"));
            assertEquals(1, number(original, "version"));
            assertContents(context.requireProgram(), ORIGINAL_FUNCTION, (byte) 0);
            Program originalProgram = context.requireProgram();
            assertTrue(originalProgram.getDomainFile().isReadOnly());
            service.open(context, PROFILE, "/program", -1);
            Program latestProgram = context.requireProgram();
            assertTrue(originalProgram.isClosed());
            assertContents(latestProgram, CHANGED_FUNCTION, (byte) 0x5a);
            service.open(context, PROFILE, "/program", 1);
            assertTrue(latestProgram.isClosed());
            assertEquals(1, context.requireProgram().getDomainFile().getVersion());
            assertContents(context.requireProgram(), ORIGINAL_FUNCTION, (byte) 0);
            service.open(context, PROFILE, "/program", -1);
            assertEquals(2, context.requireProgram().getDomainFile().getVersion());
            assertContents(context.requireProgram(), CHANGED_FUNCTION, (byte) 0x5a);
            service.open(context, PROFILE, "/program", 1);
            assertContents(context.requireProgram(), ORIGINAL_FUNCTION, (byte) 0);
            DomainFile compatibilitySource = context.project().getProjectData().getRootFolder()
                .getFile(COMPATIBILITY_PROGRAM);
            assertFalse(compatibilitySource.isCheckedOut());
            assertEquals(1, compatibilitySource.getLatestVersion());
            assertSourceNeedsMinorCompatibility(compatibilitySource);
            assertSeedOnlyHistory(compatibilitySource);
        }
    }

    private static GhidraContext context(int instance, ActiveProgram selection) {
        return new GhidraContext(null, null, instance, Map.of(), selection);
    }

    private static Map<?, ?> programEntry(Map<String, Object> listing, String name) {
        assertEquals("Fresh repository workspace must expose both remote fixtures", 2,
            number(listing, "count"));
        assertEquals(2, number(listing, "total"));
        assertEquals(false, listing.get("has_more"));
        assertEquals(false, listing.get("truncated"));
        assertEquals("/", listing.get("path"));
        assertTrue(listing.get("entries") instanceof List<?>);
        var entries = (List<?>) listing.get("entries");
        assertEquals(2, entries.size());
        for (Object entry : entries) {
            assertTrue(entry instanceof Map<?, ?>);
            var program = (Map<?, ?>) entry;
            if (!name.equals(program.get("name"))) continue;
            assertEquals("/" + name, program.get("path"));
            assertEquals("file", program.get("type"));
            return program;
        }
        throw new AssertionError("Missing synthetic program " + name);
    }

    private static int number(Map<?, ?> value, String key) {
        assertTrue("Expected numeric field " + key + ": " + value, value.get(key) instanceof Number);
        return ((Number) value.get(key)).intValue();
    }

    private static void assertSourceNeedsMinorCompatibility(DomainFile file) {
        ConnectionProfiles.withProfile(PROFILE, "ghidra", "read", profile -> {
            Object consumer = new Object();
            try {
                var object = file.getImmutableDomainObject(consumer, 1, MONITOR);
                object.release(consumer);
                fail("Stored version 1 must still require minor language compatibility changes");
            } catch (LanguageVersionException expected) {
                assertTrue(expected.getMessage(), expected.getMessage().contains("Minor language change"));
                assertNull("A minor-language fixture must not require a major translator",
                    expected.getLanguageTranslator());
            } catch (Exception failure) {
                throw new AssertionError("Could not inspect the owned synthetic source language version", failure);
            }
            return null;
        });
    }

    private static void assertSeedOnlyHistory(DomainFile file) {
        ConnectionProfiles.withProfile(PROFILE, "ghidra", "read", profile -> {
            try {
                var history = file.getVersionHistory();
                assertEquals("Readonly compatibility opening must not publish a repository version", 1,
                    history.length);
                assertEquals(1, history[0].getVersion());
                assertEquals(SEED_COMMENT, history[0].getComment());
                return null;
            } catch (java.io.IOException failure) {
                throw new AssertionError("Could not inspect owned compatibility fixture history", failure);
            }
        });
    }


    private static void assertHistory(DomainFile file) {
        assertNotNull(file);
        ConnectionProfiles.withProfile(PROFILE, "ghidra", "read", profile -> {
            try {
                var history = file.getVersionHistory();
                assertEquals("Native server must retain exactly the seeded and checked-in versions", 2,
                    history.length);
                java.util.Set<Integer> versions = new java.util.HashSet<>();
                for (var version : history) {
                    assertTrue("Native history returned a duplicate version", versions.add(version.getVersion()));
                    assertEquals("fixture_user", version.getUser());
                    assertTrue(version.getCreateTime() > 0);
                    assertEquals(version.getVersion() == 1 ? SEED_COMMENT : CHECKIN_COMMENT,
                        version.getComment());
                }
                assertEquals(java.util.Set.of(1, 2), versions);
                return null;
            } catch (java.io.IOException failure) {
                throw new AssertionError("Could not read real native repository version history", failure);
            }
        });
    }

    private static void assertContents(Program program, String functionName, byte firstByte) throws Exception {
        var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        var function = program.getFunctionManager().getFunctionAt(start);
        assertNotNull("Native reopened database lost the fixture function", function);
        assertEquals(functionName, function.getName());
        assertEquals(new AddressSet(start, start.add(15)), function.getBody());
        var block = program.getMemory().getBlock(start);
        assertNotNull("Native reopened database lost the fixture memory block", block);
        assertEquals("text", block.getName());
        assertEquals(start, block.getStart());
        assertEquals(16L, block.getSize());
        for (int offset = 0; offset < 16; offset++) {
            assertEquals(offset == 0 ? firstByte : (byte) 0,
                program.getMemory().getByte(start.add(offset)));
        }
    }
}
