package eu.starsong.ghidra.service;

import static org.junit.Assert.*;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.connection.ConnectionProfiles;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.file.H2FileFunctionDatabase;
import ghidra.features.bsim.query.protocol.CreateDatabase;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/** Real service dispatch against test-only native classes, never real services. */
public class BSimRemoteTest {
    private Path directory;
    private String oldDirectory;
    private String oldDatabase;
    private Path local;

    @Before
    public void setup() throws Exception {
        oldDirectory = System.getProperty("ghydra.connections.dir");
        oldDatabase = System.getProperty(BSimService.PROPERTY_DATABASE);
        directory = Files.createTempDirectory("bsim-profiles-");
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        local = directory.resolve("local-corpus");
        System.setProperty("ghydra.connections.dir", directory.toString());
        System.setProperty(BSimService.PROPERTY_DATABASE, local.toString());
        String localEndpoint = local.toString().replace("\\", "\\\\");
        protectedFile(".lock", "");
        protectedFile("profiles.json", "{\"version\":1,\"profiles\":{"
            + "\"pg\":{\"kind\":\"bsim\",\"backend\":\"postgresql\","
            + "\"endpoint\":\"postgresql://example.invalid:5432/corpus\",\"auth\":\"password\","
            + "\"credential_ref\":\"synthetic\",\"permissions\":[\"query\",\"ingest\"]},"
            + "\"elastic\":{\"kind\":\"bsim\",\"backend\":\"elasticsearch\","
            + "\"endpoint\":\"elastic://example.invalid:9200/corpus\",\"auth\":\"password\","
            + "\"credential_ref\":\"synthetic\",\"permissions\":[\"query\",\"ingest\"]},"
            + "\"reader\":{\"kind\":\"bsim\",\"backend\":\"postgresql\","
            + "\"endpoint\":\"postgresql://example.invalid:5432/corpus\",\"auth\":\"password\","
            + "\"credential_ref\":\"synthetic\",\"permissions\":[\"query\"]},"
            + "\"local\":{\"kind\":\"bsim\",\"backend\":\"h2\",\"endpoint\":\""
            + localEndpoint + "\",\"auth\":\"none\",\"permissions\":[\"query\",\"ingest\"]}}}");
        protectedFile("credentials.json", "{\"version\":1,\"credentials\":{\"synthetic\":{"
            + "\"username\":\"synthetic-user\",\"password\":\"synthetic-secret\"}}}");
        BSimClientFactory.builds = 0;
        BSimClientFactory.initializeResult = true;
        BSimClientFactory.throwOnInitialize = false;
        BSimClientFactory.connectionType = "SSL_Authentication";
        H2FileFunctionDatabase.builds = 0;
        H2FileFunctionDatabase.closes = 0;
        CreateDatabase.executions = 0;
    }

    private void protectedFile(String name, String content) throws Exception {
        Path file = directory.resolve(name);
        Files.writeString(file, content);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    }

    @After
    public void cleanup() throws Exception {
        restore("ghydra.connections.dir", oldDirectory);
        restore(BSimService.PROPERTY_DATABASE, oldDatabase);
        if (directory != null) {
            try (var files = Files.walk(directory)) {
                for (Path file : files.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(file);
                }
            }
        }
    }

    private static void restore(String property, String value) {
        if (value == null) System.clearProperty(property);
        else System.setProperty(property, value);
    }

    @Test
    public void remote_backends_use_native_factory_and_never_create() {
        for (String profile : new String[] { "pg", "elastic" }) {
            ConnectionProfiles.withProfile(profile, "bsim", "ingest", selected -> {
                Map<String, Object> data = new LinkedHashMap<>();
                Object connection = BSimDatabase.open(BSimService.database(), true, data);
                assertNotNull(data.toString(), connection);
                assertEquals(profile.equals("pg") ? BSimServerInfo.DBType.postgres
                    : BSimServerInfo.DBType.elastic, BSimClientFactory.selected.type);
                assertFalse(BSimClientFactory.asynchronous);
                assertEquals("synthetic-user", BSimClientFactory.selected.username);
                assertEquals(Boolean.FALSE, data.get("created"));
                assertEquals(0, CreateDatabase.executions);
                assertEquals(0, H2FileFunctionDatabase.builds);
                BSimDatabase.release(connection, BSimService.database());
                assertEquals(1, BSimClientFactory.lastClient.closes);
                return null;
            });
        }
    }

    @Test
    public void remote_status_and_diff_eligibility_do_not_probe_files_or_connect() {
        ConnectionProfiles.withProfile("pg", "bsim", null, selected -> {
            assertTrue(BSimService.databaseExists());
            Map<String, Object> status = BSimService.status();
            assertEquals("pg", status.get("database"));
            assertNull(status.get("database_exists"));
            assertEquals(Boolean.TRUE, status.get("ready"));
            assertEquals(Boolean.FALSE, status.get("connection_checked"));
            assertFalse(status.toString().contains("example.invalid"));
            assertFalse(status.toString().contains("synthetic"));
            assertEquals(0, BSimClientFactory.builds);
            return null;
        });
    }

    @Test
    public void missing_remote_database_and_native_exception_are_safe_and_closed() {
        ConnectionProfiles.withProfile("pg", "bsim", "ingest", selected -> {
            for (boolean exception : new boolean[] { false, true }) {
                BSimClientFactory.initializeResult = false;
                BSimClientFactory.throwOnInitialize = exception;
                Map<String, Object> data = new LinkedHashMap<>();
                assertNull(BSimDatabase.open(BSimService.database(), true, data));
                assertEquals("BSIM_INIT_FAILED", data.get("code"));
                assertFalse(data.toString().contains("private-host"));
                assertFalse(data.toString().contains("secret"));
                assertEquals(0, CreateDatabase.executions);
                assertEquals(1, BSimClientFactory.lastClient.closes);
            }
            return null;
        });
    }

    @Test
    public void unauthenticated_remote_connection_is_closed_before_use() {
        ConnectionProfiles.withProfile("pg", "bsim", "query", selected -> {
            BSimClientFactory.connectionType = "Unencrypted_No_Authentication";
            Map<String, Object> data = new LinkedHashMap<>();
            assertNull(BSimDatabase.open(BSimService.database(), false, data));
            assertEquals("BSIM_INIT_FAILED", data.get("code"));
            assertEquals(1, BSimClientFactory.lastClient.closes);
            return null;
        });
    }

    @Test
    public void denied_ingest_never_enters_operation_or_opens_client() {
        AtomicBoolean entered = new AtomicBoolean();
        try {
            ConnectionProfiles.withProfile("reader", "bsim", "ingest", selected -> {
                entered.set(true);
                return BSimIngestService.ingest(null, 1);
            });
            fail("ingest permission must be enforced before invoking the operation");
        } catch (ConnectionException denied) {
            assertEquals("CONNECTION_PERMISSION_DENIED", denied.code());
        }
        assertFalse(entered.get());
        assertEquals(0, BSimClientFactory.builds);
    }

    @Test
    public void h2_creation_and_legacy_selection_are_preserved_and_scoped() {
        ConnectionProfiles.withProfile("local", "bsim", "ingest", selected -> {
            Map<String, Object> data = new LinkedHashMap<>();
            Object connection = BSimDatabase.open(BSimService.database(), true, data);
            assertNotNull(data.toString(), connection);
            assertEquals(Boolean.TRUE, data.get("created"));
            assertEquals(1, CreateDatabase.executions);
            assertEquals(local.toString(), H2FileFunctionDatabase.selected.database);
            BSimDatabase.release(connection, BSimService.database());
            return null;
        });
        assertEquals(local.toString(), BSimService.database());
        assertEquals(local.toString(), System.getProperty(BSimService.PROPERTY_DATABASE));
        assertEquals(0, BSimClientFactory.builds);
        assertEquals(1, H2FileFunctionDatabase.closes);
    }

    @Test
    public void missing_local_query_does_not_create_or_leave_a_handle() throws Exception {
        Map<String, Object> data = new LinkedHashMap<>();
        assertNull(BSimDatabase.open(local.toString(), false, data));
        assertEquals("BSIM_NO_DATABASE", data.get("code"));
        assertEquals(0, H2FileFunctionDatabase.builds);
        assertEquals(0, CreateDatabase.executions);
        Files.writeString(Path.of(local + ".mv.db"), "");
        assertTrue(BSimService.databaseExists());
        Object connection = BSimDatabase.open(local.toString(), false, new LinkedHashMap<>());
        assertNotNull(connection);
        assertEquals(0, CreateDatabase.executions);
        BSimDatabase.release(connection, local.toString());
    }

    @Test
    public void default_profile_is_selected_without_mutating_legacy_configuration() throws Exception {
        Path manifest = directory.resolve("profiles.json");
        protectedFile("profiles.json", Files.readString(manifest).replace(
            "\"version\":1", "\"version\":1,\"default_bsim\":\"pg\""));
        ConnectionProfiles.withProfile(null, "bsim", "query", selected -> {
            assertEquals("pg", BSimService.database());
            assertTrue(BSimService.databaseExists());
            assertEquals(local.toString(), System.getProperty(BSimService.PROPERTY_DATABASE));
            return null;
        });
    }

    @Test
    public void failed_operation_restores_previous_selection() {
        try {
            ConnectionProfiles.withProfile("pg", "bsim", "query", selected -> {
                throw new IllegalStateException("synthetic failure");
            });
            fail("the operation must propagate its failure");
        } catch (IllegalStateException expected) {
            assertEquals("synthetic failure", expected.getMessage());
        }
        assertEquals(local.toString(), BSimService.database());
    }

    @Test
    public void legacy_urls_are_rejected_without_echoing_credentials() {
        System.setProperty(BSimService.PROPERTY_DATABASE,
            "postgresql://private-user:private-secret@private-host/corpus");
        try {
            BSimService.status();
            fail("remote URLs must require a worker profile");
        } catch (IllegalArgumentException rejected) {
            assertFalse(rejected.getMessage().contains("private-"));
        }
        assertEquals("C:\\corpus\\sample", BSimService.localPath("C:\\corpus\\sample"));
        assertEquals("./corpus/sample", BSimService.localPath("./corpus/sample"));
    }

    @Test public void repositoryProgramMetadataRetainsItsProjectAndFolder() throws Exception {
        var url = new java.net.URL(null, "ghidra://example.invalid:13100/corpus/folder/program",
            new ghidra.framework.protocol.ghidra.Handler());
        var file = (ghidra.framework.model.DomainFile) java.lang.reflect.Proxy.newProxyInstance(
            getClass().getClassLoader(), new Class<?>[] { ghidra.framework.model.DomainFile.class },
            (proxy, method, args) -> {
                if (method.getName().equals("getSharedProjectURL")) return url;
                throw new AssertionError(method.getName());
            });
        var program = (ghidra.program.model.listing.Program) java.lang.reflect.Proxy.newProxyInstance(
            getClass().getClassLoader(), new Class<?>[] { ghidra.program.model.listing.Program.class },
            (proxy, method, args) -> {
                if (method.getName().equals("getDomainFile")) return file;
                throw new AssertionError(method.getName());
            });
        String[] location = BSimDatabase.projectLocation(program);
        assertNull(location[2]);
        assertEquals("/folder", location[1]);
        var project = new java.net.URL(null, location[0], new ghidra.framework.protocol.ghidra.Handler());
        assertEquals("example.invalid", project.getHost());
        assertEquals(13100, project.getPort());
        assertEquals("corpus", ghidra.framework.protocol.ghidra.GhidraURL.getRepositoryName(project));
    }
}
