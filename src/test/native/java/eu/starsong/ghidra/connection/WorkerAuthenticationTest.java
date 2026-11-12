package eu.starsong.ghidra.connection;

import static org.junit.Assert.*;
import ghidra.framework.client.ClientUtil;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import org.junit.*;

/** Shared native task pools must receive only the selected endpoint's live credential lease. */
public class WorkerAuthenticationTest {
    private static final AtomicInteger IDS = new AtomicInteger();
    private Path root;
    private String oldDirectory;
    private String host;

    @Before public void setup() throws Exception {
        oldDirectory = System.getProperty(ConnectionProfiles.PROPERTY);
        root = Files.createTempDirectory("ghydra-auth-scope-");
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
        host = "native-task-" + IDS.incrementAndGet() + ".invalid";
        file(".lock", "");
        profile(host, "original");
        file("credentials.json", "{\"version\":1,\"credentials\":{"
            + "\"original\":{\"username\":\"old-user\",\"password\":\"old-private-password\"},"
            + "\"replacement\":{\"username\":\"new-user\",\"password\":\"new-private-password\"}}}");
        System.setProperty(ConnectionProfiles.PROPERTY, root.toString());
    }

    private void file(String name, String value) throws Exception {
        Path path = root.resolve(name);
        Files.writeString(path, value);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
    private void profile(String server, String reference) throws Exception {
        file("profiles.json", "{\"version\":1,\"profiles\":{\"repo\":{\"kind\":\"ghidra\","
            + "\"backend\":\"ghidra\",\"endpoint\":\"ghidra://" + server + "/corpus\","
            + "\"auth\":\"password\",\"credential_ref\":\"" + reference + "\",\"permissions\":[\"read\"]}}}");
    }

    private String[] password(String server) { return password(server, true); }

    private String[] password(String server, boolean selectUser) {
        var name = selectUser ? new NameCallback("User", "unselected") : null;
        var password = new PasswordCallback("Password", false);
        boolean accepted = ClientUtil.getClientAuthenticator().processPasswordCallbacks(
            "Repository Server Authentication", "Repository Server", server, selectUser,
            name, password, null, null, null);
        try {
            return accepted ? new String[] { name == null ? ClientUtil.getUserName() : name.getName(),
                new String(password.getPassword()) } : null;
        } finally { password.clearPassword(); }
    }

    private void passwordIdentity(String username) throws Exception {
        file("credentials.json", new com.google.gson.Gson().toJson(java.util.Map.of(
            "version", 1, "credentials", java.util.Map.of("original", java.util.Map.of(
                "username", username, "password", "private-test-password")))));
    }

    @Test public void existingNativeTaskThreadUsesOnlyBoundEndpointWhileScopeIsLive() throws Exception {
        var pool = Executors.newSingleThreadExecutor();
        try {
            pool.submit(() -> Boolean.TRUE).get(5, TimeUnit.SECONDS); // thread predates the scope
            ConnectionProfiles.withProfile("repo", "ghidra", "read", selected -> {
                try {
                    assertArrayEquals(new String[] { "old-user", "old-private-password" },
                        pool.submit(() -> password(host)).get(5, TimeUnit.SECONDS));
                    assertNull(pool.submit(() -> password("another-server.invalid")).get(5, TimeUnit.SECONDS));
                    return null;
                } catch (Exception failure) { throw new AssertionError(failure); }
            });
            assertNull(pool.submit(() -> password(host)).get(5, TimeUnit.SECONDS));
        } finally { pool.shutdownNow(); }
    }

    @Test public void replacingProfileCannotRetargetAnExistingAuthenticationSnapshot() throws Exception {
        ConnectionProfiles.withProfile("repo", "ghidra", "read", selected -> {
            try { profile("replacement.invalid", "replacement"); }
            catch (Exception failure) { throw new AssertionError(failure); }
            assertEquals("ghidra://" + host + "/corpus", selected.endpoint());
            assertNull(password("replacement.invalid"));
            assertArrayEquals(new String[] { "old-user", "old-private-password" }, password(host));
            return null;
        });
        assertEquals("replacement.invalid", java.net.URI.create(
            ConnectionProfiles.require("repo", "ghidra", "read").endpoint()).getHost());
        assertNull(password(host));
        assertNull(password("replacement.invalid"));
    }

    @Test public void missingUsernameCallbackCannotSelectAnotherNativeAccount() throws Exception {
        String nativeUser = ClientUtil.getUserName();
        passwordIdentity("not-" + nativeUser);
        ConnectionProfiles.withProfile("repo", "ghidra", "read", selected -> {
            assertNull(password(host, false));
            assertArrayEquals(new String[] { "not-" + nativeUser, "private-test-password" }, password(host));
            return null;
        });
        passwordIdentity(nativeUser);
        ConnectionProfiles.withProfile("repo", "ghidra", "read", selected -> {
            assertArrayEquals(new String[] { nativeUser, "private-test-password" }, password(host, false));
            return null;
        });
    }

    @Test public void sshSignsWithoutOptionalUsernameOnlyForMatchingNativeIdentity() throws Exception {
        var generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        var encoded = new java.io.StringWriter();
        try (var pem = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(encoded)) {
            pem.writeObject(pair.getPrivate());
        }
        file("identity.pem", encoded.toString());
        file("profiles.json", new com.google.gson.Gson().toJson(java.util.Map.of(
            "version", 1, "profiles", java.util.Map.of("repo", java.util.Map.of(
                "kind", "ghidra", "backend", "ghidra", "endpoint", "ghidra://" + host + "/corpus",
                "auth", "ssh", "credential_ref", "original", "permissions", java.util.List.of("read"))))));
        String nativeUser = ClientUtil.getUserName();
        for (boolean matching : new boolean[] { true, false }) {
            file("credentials.json", new com.google.gson.Gson().toJson(java.util.Map.of(
                "version", 1, "credentials", java.util.Map.of("original", java.util.Map.of(
                    "username", matching ? nativeUser : "not-" + nativeUser,
                    "key_store", root.resolve("identity.pem").toString())))));
            ConnectionProfiles.withProfile("repo", "ghidra", "read", selected -> {
                var callback = new ghidra.framework.remote.SSHSignatureCallback(new byte[32], new byte[32]);
                assertEquals(matching, ClientUtil.getClientAuthenticator().processSSHSignatureCallbacks(
                    host, null, callback));
                assertEquals(matching, callback.isSigned());
                return null;
            });
        }
    }

    @Test public void nativeAuthenticatedAccountMustMatchSelectedProfile() {
        ConnectionProfiles.withProfile("repo", "ghidra", "read", selected -> {
            WorkerAuthentication.verifyRepositoryIdentity(selected, "old-user");
            for (String wrong : new String[] { null, "another-native-account" }) {
                try {
                    WorkerAuthentication.verifyRepositoryIdentity(selected, wrong);
                    fail("An account mismatch must be refused");
                } catch (ConnectionException expected) {
                    assertEquals("CONNECTION_AUTH_FAILED", expected.code());
                    assertFalse(expected.getMessage().contains("another-native-account"));
                }
            }
            return null;
        });
    }

    @After public void cleanup() throws Exception {
        if (oldDirectory == null) System.clearProperty(ConnectionProfiles.PROPERTY);
        else System.setProperty(ConnectionProfiles.PROPERTY, oldDirectory);
        try (var files = Files.walk(root)) {
            for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }
}
