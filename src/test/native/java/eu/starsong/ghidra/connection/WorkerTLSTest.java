package eu.starsong.ghidra.connection;

import static org.junit.Assert.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Comparator;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;
import org.junit.*;

/** Real bounded TLS exchanges, including native context-cache restoration. */
public class WorkerTLSTest {
    private static Path root;
    private static SSLContext serverContext;
    private String oldDirectory;
    private String oldCertificates;

    @BeforeClass public static void certificate() throws Exception {
        root = Files.createTempDirectory("ghydra-test-tls-");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        run(keytool, "-genkeypair", "-alias", "test", "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "1", "-dname", "CN=localhost", "-ext", "SAN=dns:localhost",
            "-keystore", root.resolve("server.p12").toString(), "-storetype", "PKCS12",
            "-storepass", "synthetic-test", "-keypass", "synthetic-test", "-noprompt");
        run(keytool, "-exportcert", "-rfc", "-alias", "test", "-keystore",
            root.resolve("server.p12").toString(), "-storepass", "synthetic-test",
            "-file", root.resolve("ca.pem").toString());
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(root.resolve("server.p12"))) {
            store.load(input, "synthetic-test".toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, "synthetic-test".toCharArray());
        serverContext = SSLContext.getInstance("TLS", "SunJSSE");
        serverContext.init(keys.getKeyManagers(), null, null);
    }

    private static void run(String... command) throws Exception {
        Process child = new ProcessBuilder(command).redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        try {
            assertTrue("test certificate generation timed out", child.waitFor(20, TimeUnit.SECONDS));
            assertEquals("test certificate generation failed", 0, child.exitValue());
        } finally { child.destroyForcibly(); }
    }

    @Before public void scope() {
        oldDirectory = System.getProperty(ConnectionProfiles.PROPERTY);
        oldCertificates = System.getProperty("ghidra.cacerts");
        System.setProperty(ConnectionProfiles.PROPERTY, root.toString());
        System.clearProperty("ghidra.cacerts");
    }

    @After public void restore() {
        restore(ConnectionProfiles.PROPERTY, oldDirectory);
        restore("ghidra.cacerts", oldCertificates);
    }
    private static void restore(String key, String value) {
        if (value == null) System.clearProperty(key); else System.setProperty(key, value);
    }

    private SSLSocketFactory nativeSockets() throws Exception {
        WorkerTLS.initialize();
        // This used to restore Ghidra's permissive cached context over a strict default.
        Class<?> initializer;
        Class<?> factory;
        try { initializer = Class.forName("ghidra.net.DefaultSSLContextInitializer"); }
        catch (ClassNotFoundException older) { initializer = Class.forName("ghidra.net.SSLContextInitializer"); }
        assertEquals(Boolean.TRUE, initializer.getMethod("initialize", boolean.class).invoke(null, true));
        try { factory = Class.forName("ghidra.net.DefaultSSLSocketFactory"); }
        catch (ClassNotFoundException older) { factory = Class.forName("ghidra.net.ApplicationSSLSocketFactory"); }
        return (SSLSocketFactory) factory.getConstructor().newInstance();
    }

    @FunctionalInterface private interface Connect {
        SSLSocket open(int port) throws Exception;
    }

    private int exchange(SSLSocketFactory clientFactory, String hostname) throws Exception {
        return exchange(port -> {
            Socket tcp = new Socket(InetAddress.getLoopbackAddress(), port);
            try {
                return (SSLSocket) clientFactory.createSocket(tcp, hostname, port, true);
            } catch (Exception failure) {
                tcp.close();
                throw failure;
            }
        });
    }

    private int exchange(Connect connector) throws Exception {
        var executor = Executors.newSingleThreadExecutor();
        try (SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(4000);
            var responder = executor.submit(() -> {
                try (SSLSocket accepted = (SSLSocket) server.accept()) {
                    accepted.setSoTimeout(4000);
                    int value = accepted.getInputStream().read();
                    accepted.getOutputStream().write(value + 1);
                    return value;
                }
            });
            try (SSLSocket client = connector.open(server.getLocalPort())) {
                client.setSoTimeout(4000);
                client.startHandshake();
                client.getOutputStream().write(42);
                int answer = client.getInputStream().read();
                assertEquals(Integer.valueOf(42), responder.get(5, TimeUnit.SECONDS));
                return answer;
            }
        } finally {
            executor.shutdownNow();
            assertTrue("TLS responder did not stop", executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test public void untrustedServerCannotCompleteNativeHandshake() throws Exception {
        assertThrows(SSLHandshakeException.class, () -> exchange(nativeSockets(), "localhost"));
    }

    @Test public void trustedCertificateCannotAuthenticateAnotherHostname() throws Exception {
        System.setProperty("ghidra.cacerts", root.resolve("ca.pem").toString());
        assertThrows(SSLHandshakeException.class,
            () -> exchange(nativeSockets(), "another-host.invalid"));
    }

    @Test public void trustedMatchingServerExchangesDataThroughNativeFactory() throws Exception {
        System.setProperty("ghidra.cacerts", root.resolve("ca.pem").toString());
        assertEquals(43, exchange(nativeSockets(), "localhost"));
    }

    @Test public void nativeRmiFactoryRetainsVerifiedHostnameChecks() throws Exception {
        System.setProperty("ghidra.cacerts", root.resolve("ca.pem").toString());
        nativeSockets();
        var rmi = new javax.rmi.ssl.SslRMIClientSocketFactory();
        assertThrows(SSLHandshakeException.class,
            () -> exchange(port -> (SSLSocket) rmi.createSocket("127.0.0.1", port)));
    }

    @Test public void nativeRmiFactoryExchangesDataWithTrustedMatchingServer() throws Exception {
        System.setProperty("ghidra.cacerts", root.resolve("ca.pem").toString());
        nativeSockets();
        var rmi = new javax.rmi.ssl.SslRMIClientSocketFactory();
        assertEquals(43, exchange(port -> (SSLSocket) rmi.createSocket("localhost", port)));
    }

    @AfterClass public static void cleanup() throws Exception {
        if (root == null) return;
        try (var files = Files.walk(root)) {
            for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }
}
