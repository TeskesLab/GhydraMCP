package eu.starsong.ghidra.connection;

import static org.junit.Assert.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;
import org.junit.Test;

/** A separate JVM isolates the native process-wide certificate identity and SSL caches. */
public class WorkerPkiTest {
    @Test public void selectedNativeCertificateAuthenticatesTlsClient() throws Exception {
        Path root = Files.createTempDirectory("ghydra-native-pki-");
        Process child = null;
        try {
            Path log = root.resolve("probe.log");
            ProcessBuilder command = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Djava.awt.headless=true", "-Duser.home=" + root,
                "-cp", System.getProperty("java.class.path"), Probe.class.getName(),
                System.getProperty("ghydra.test.ghidraHome"), root.toString());
            command.environment().clear();
            command.environment().put("HOME", root.toString());
            command.redirectErrorStream(true).redirectOutput(log.toFile());
            child = command.start();
            assertTrue("Native PKI probe timed out", child.waitFor(90, TimeUnit.SECONDS));
            assertEquals(Files.readString(log), 0, child.exitValue());
        } finally {
            if (child != null && child.isAlive()) {
                child.destroyForcibly();
                assertTrue("Native PKI probe did not stop", child.waitFor(5, TimeUnit.SECONDS));
            }
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
    }

    public static final class Probe {
        public static void main(String[] args) {
            try { run(Path.of(args[0]), Path.of(args[1])); System.exit(0); }
            catch (Throwable failure) { failure.printStackTrace(); System.exit(1); }
        }

        private static void privateFile(Path path, String content) throws Exception {
            Files.writeString(path, content);
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        }

        private static void keytool(String... args) throws Exception {
            var command = new java.util.ArrayList<String>();
            command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
            command.addAll(java.util.List.of(args));
            Process child = new ProcessBuilder(command).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
            try {
                assertTrue(child.waitFor(20, TimeUnit.SECONDS));
                assertEquals(0, child.exitValue());
            } finally {
                if (child.isAlive()) {
                    child.destroyForcibly();
                    assertTrue("Keytool did not stop", child.waitFor(5, TimeUnit.SECONDS));
                }
            }
        }

        private static void run(Path install, Path root) throws Exception {
            Path identity = root.resolve("identity.p12");
            Path certificate = root.resolve("ca.pem");
            keytool("-genkeypair", "-alias", "test", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "1", "-dname", "CN=localhost", "-ext", "SAN=dns:localhost",
                "-ext", "KU=digitalSignature,keyEncipherment", "-ext", "EKU=clientAuth,serverAuth",
                "-keystore", identity.toString(), "-storetype", "PKCS12",
                "-storepass", "synthetic-test", "-keypass", "synthetic-test", "-noprompt");
            Files.setPosixFilePermissions(identity, PosixFilePermissions.fromString("rw-------"));
            keytool("-exportcert", "-rfc", "-alias", "test", "-keystore", identity.toString(),
                "-storepass", "synthetic-test", "-file", certificate.toString());
            privateFile(root.resolve(".lock"), "");
            var gson = new com.google.gson.Gson();
            privateFile(root.resolve("profiles.json"), gson.toJson(Map.of("version", 1, "profiles", Map.of(
                "identity", Map.of("kind", "ghidra", "backend", "ghidra", "endpoint",
                    "ghidra://localhost:13100/fixture", "auth", "pki", "credential_ref", "test",
                    "permissions", java.util.List.of("read"))))));
            privateFile(root.resolve("credentials.json"), gson.toJson(Map.of("version", 1, "credentials", Map.of(
                "test", Map.of("username", "fixture-pki", "key_store", identity.toString(),
                    "key_store_password", "synthetic-test")))));
            System.setProperty("ghidra.cacerts", certificate.toString());
            Application.initializeApplication(new GhidraApplicationLayout(install.toFile()),
                new HeadlessGhidraApplicationConfiguration());
            System.setProperty(ConnectionProfiles.PROPERTY, root.toString());
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(identity)) { store.load(input, "synthetic-test".toCharArray()); }
            KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, "synthetic-test".toCharArray());
            TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            SSLContext serverContext = SSLContext.getInstance("TLS", "SunJSSE");
            serverContext.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
            var executor = Executors.newSingleThreadExecutor();
            try (SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory()
                    .createServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
                server.setSoTimeout(5000);
                server.setNeedClientAuth(true);
                var accepted = executor.submit(() -> {
                    try (SSLSocket socket = (SSLSocket) server.accept()) {
                        socket.setSoTimeout(5000);
                        socket.startHandshake();
                        assertArrayEquals(store.getCertificate("test").getEncoded(),
                            socket.getSession().getPeerCertificates()[0].getEncoded());
                        int value = socket.getInputStream().read();
                        socket.getOutputStream().write(value + 1);
                        return value;
                    }
                });
                ConnectionProfiles.withProfile("identity", "ghidra", "read", profile -> {
                    try (SSLSocket socket = (SSLSocket) SSLContext.getDefault().getSocketFactory()
                            .createSocket("localhost", server.getLocalPort())) {
                        socket.setSoTimeout(5000);
                        socket.startHandshake();
                        socket.getOutputStream().write(42);
                        assertEquals(43, socket.getInputStream().read());
                        return true;
                    } catch (Exception failed) { throw new AssertionError("Native PKI exchange failed", failed); }
                });
                assertEquals(Integer.valueOf(42), accepted.get(5, TimeUnit.SECONDS));
            } finally {
                executor.shutdownNow();
                assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
            }
        }
    }
}
