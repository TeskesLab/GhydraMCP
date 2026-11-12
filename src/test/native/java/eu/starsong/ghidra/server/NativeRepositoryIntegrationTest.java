package eu.starsong.ghidra.server;

import static org.junit.Assert.*;

import eu.starsong.ghidra.connection.ConnectionProfiles;
import ghidra.server.CommandProcessor;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.Test;

/** A private native server and fresh client JVM, never an installed service or operator store. */
public class NativeRepositoryIntegrationTest {
    private static final String HELPER = NativeRepositoryIntegrationClient.class.getName();
    private static final String SYNTHETIC_PASSWORD = "synthetic-test";

    @Test public void realConnectorOpensMinorCompatibilityViewsAndPersistsAcrossWorkspaceReopens() throws Exception {
        Path root = Files.createTempDirectory("ghydra-native-repository-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Process server = null;
        Path serverOutput = root.resolve("server-output.log");
        boolean passed = false;
        try {
            String ghidraHome = System.getProperty("ghydra.test.ghidraHome");
            assertNotNull("NativeConnectionTests must supply the installed Ghidra home", ghidraHome);
            Path repositories = directory(root.resolve("repos"));
            Path store = directory(root.resolve("store"));
            Path client = processDirectories(root.resolve("client"));
            Path admin = processDirectories(root.resolve("admin"));
            Path serverState = processDirectories(root.resolve("server"));
            Path keyStore = root.resolve("server.p12");
            Path ca = root.resolve("ca.pem");
            String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
            runOwned(root, root.resolve("keytool-generate.log"), 20, List.of(keytool,
                "-J-Duser.home=" + client.resolve("home"),
                "-J-Djava.io.tmpdir=" + client.resolve("tmp"),
                "-genkeypair", "-alias", "fixture", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", "CN=127.0.0.1",
                "-ext", "SAN=ip:127.0.0.1", "-ext", "KU=digitalSignature,keyEncipherment",
                "-ext", "EKU=serverAuth,clientAuth", "-keystore", keyStore.toString(),
                "-storetype", "PKCS12", "-storepass", SYNTHETIC_PASSWORD,
                "-keypass", SYNTHETIC_PASSWORD, "-noprompt"));
            Files.setPosixFilePermissions(keyStore, PosixFilePermissions.fromString("rw-------"));
            runOwned(root, root.resolve("keytool-export.log"), 20, List.of(keytool,
                "-J-Duser.home=" + client.resolve("home"), "-exportcert", "-rfc", "-alias", "fixture",
                "-keystore", keyStore.toString(), "-storepass", SYNTHETIC_PASSWORD,
                "-file", ca.toString()));
            Files.setPosixFilePermissions(ca, PosixFilePermissions.fromString("rw-------"));

            int base = freeContiguousPorts();
            privateFile(store.resolve(".lock"), "");
            privateFile(store.resolve("profiles.json"), """
                {"version":1,"profiles":{"native-fixture":{"kind":"ghidra","backend":"ghidra",
                "endpoint":"ghidra://127.0.0.1:%d/corpus","auth":"password","credential_ref":"fixture",
                "permissions":["read","checkout","checkin"]}}}
                """.formatted(base));
            privateFile(store.resolve("credentials.json"), """
                {"version":1,"credentials":{"fixture":{"username":"fixture_user","password":"changeme"}}}
                """);
            Path configuration = root.resolve("server-test.conf");
            privateFile(configuration, "ghidra.repositories.dir=" + repositories + "\n");

            List<String> serverCommand = javaCommand(serverState);
            serverCommand.addAll(List.of("-Dghidra.keystore=" + keyStore,
                "-Dghidra.password=" + SYNTHETIC_PASSWORD, "ghidra.server.remote.GhidraServer",
                "-a0", "-u", "-e0", "-i", "127.0.0.1", "-ip", "127.0.0.1",
                "-p" + base, repositories.toString()));
            server = start(root, serverOutput, serverCommand);
            Path commands = commandDirectory(repositories);
            awaitServer(server, commands, base);

            // Watch before enqueueing: the server may consume the command before admin exits.
            // Only filenames/events are inspected; the native password database is never read.
            try (WatchService watcher = commands.getFileSystem().newWatchService()) {
                commands.register(watcher, StandardWatchEventKinds.ENTRY_DELETE);
                List<String> adminCommand = javaCommand(admin);
                adminCommand.addAll(List.of(HELPER, "admin", ghidraHome, configuration.toString()));
                runOwned(root, root.resolve("admin-output.log"), 30, adminCommand);
                awaitAdminProcessing(server, watcher);
            }

            List<String> clientCommand = javaCommand(client);
            // The production key is ghydra.connections.dir, not ghidra.connections.dir.
            clientCommand.addAll(List.of("-D" + ConnectionProfiles.PROPERTY + "=" + store,
                "-Dghidra.cacerts=" + ca, HELPER, "workflow", ghidraHome,
                root.toString(), Integer.toString(base)));
            String output = runOwned(root, root.resolve("client-output.log"), 120, clientCommand);
            assertTrue("Child exited without a native regression verdict:\n" + output,
                output.contains("NATIVE_REPOSITORY_INTEGRATION_PASSED"));
            passed = true;
        } finally {
            try {
                terminate(server);
                if (!passed && Files.exists(serverOutput)) {
                    System.err.println("Owned native server diagnostics:\n" + Files.readString(serverOutput));
                }
            } finally {
                deleteTree(root);
            }
        }
    }

    private static Path directory(Path path) throws IOException {
        return Files.createDirectory(path,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }

    private static Path processDirectories(Path path) throws IOException {
        directory(path);
        for (String name : List.of("home", "tmp", "cache", "settings", "state")) {
            directory(path.resolve(name));
        }
        return path;
    }

    private static void privateFile(Path path, String content) throws IOException {
        Files.createFile(path,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(path, content);
    }

    private static List<String> javaCommand(Path state) {
        String classpath = Arrays.stream(System.getProperty("java.class.path").split(File.pathSeparator))
            .map(item -> Path.of(item).toAbsolutePath().toString())
            .collect(Collectors.joining(File.pathSeparator));
        return new ArrayList<>(List.of(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx512m",
            "-Djava.awt.headless=true", "-Djava.net.preferIPv4Stack=true",
            "-Duser.home=" + state.resolve("home"), "-Djava.io.tmpdir=" + state.resolve("tmp"),
            "-Dapplication.tempdir=" + state.resolve("tmp"),
            "-Dapplication.cachedir=" + state.resolve("cache"),
            "-Dapplication.settingsdir=" + state.resolve("settings"),
            "-cp", classpath));
    }

    private static Process start(Path root, Path output, List<String> command) throws IOException {
        privateFile(output, "");
        ProcessBuilder builder = new ProcessBuilder(command).directory(root.toFile())
            .redirectErrorStream(true).redirectOutput(output.toFile());
        var environment = builder.environment();
        environment.clear();
        for (String key : List.of("PATH", "LANG", "LC_ALL")) {
            String value = System.getenv(key);
            if (value != null) environment.put(key, value);
        }
        environment.put("HOME", root.toString());
        environment.put("TMPDIR", root.resolve("client/tmp").toString());
        environment.put("GHYDRA_STATE_DIR", root.resolve("client/state").toString());
        return builder.start();
    }

    private static String runOwned(Path root, Path output, long seconds, List<String> command)
            throws Exception {
        Process child = start(root, output, command);
        try {
            boolean exited = child.waitFor(seconds, TimeUnit.SECONDS);
            String text = Files.readString(output);
            assertTrue("Owned fixture process timed out (" + output.getFileName() + "):\n" + text, exited);
            assertEquals("Owned fixture process failed (" + output.getFileName() + "):\n" + text,
                0, child.exitValue());
            return text;
        } finally {
            terminate(child);
        }
    }


    private static Path commandDirectory(Path repositories) throws Exception {
        var method = CommandProcessor.class.getDeclaredMethod("getCommandDir", File.class);
        method.setAccessible(true);
        return ((File) method.invoke(null, repositories.toFile())).toPath();
    }

    private static int freeContiguousPorts() throws IOException {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        for (int attempt = 0; attempt < 100; attempt++) {
            try (ServerSocket first = new ServerSocket(0, 1, loopback)) {
                int base = first.getLocalPort();
                if (base > 65533 || (base <= 45120 && base + 2 >= 45100)) continue;
                try (ServerSocket second = new ServerSocket(base + 1, 1, loopback);
                     ServerSocket third = new ServerSocket(base + 2, 1, loopback)) {
                    return base;
                } catch (java.net.BindException occupied) {
                    // Reserve all three together before choosing the fixture's base port.
                }
            }
        }
        throw new IOException("Could not reserve three contiguous loopback fixture ports");
    }

    private static void awaitServer(Process server, Path commands, int base) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(40);
        while (System.nanoTime() < deadline) {
            assertTrue("Owned native server exited before readiness", server.isAlive());
            if (Files.isDirectory(commands) && listening(base) && listening(base + 1)
                    && listening(base + 2)) return;
            Thread.sleep(50);
        }
        fail("Owned native server did not become ready within 40 seconds");
    }

    private static boolean listening(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 100);
            return true;
        } catch (IOException notReady) {
            return false;
        }
    }

    private static void awaitAdminProcessing(Process server, WatchService watcher) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (System.nanoTime() < deadline) {
            assertTrue("Owned server exited before processing synthetic user", server.isAlive());
            var key = watcher.poll(200, TimeUnit.MILLISECONDS);
            if (key == null) continue;
            boolean processed = false;
            for (var event : key.pollEvents()) {
                assertNotEquals("Fixture command watcher overflowed",
                    StandardWatchEventKinds.OVERFLOW, event.kind());
                if (event.kind() == StandardWatchEventKinds.ENTRY_DELETE
                        && event.context().toString().endsWith(".cmd")) processed = true;
            }
            assertTrue("Fixture command directory disappeared", key.reset());
            if (processed) return;
        }
        fail("Server did not process synthetic user command within 20 seconds");
    }

    private static void terminate(Process process) {
        if (process == null || !process.isAlive()) return;
        boolean interrupted = Thread.interrupted();
        try {
            process.destroy();
            try {
                if (process.waitFor(5, TimeUnit.SECONDS)) return;
            } catch (InterruptedException failure) {
                interrupted = true;
            }
            process.destroyForcibly();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (process.isAlive() && System.nanoTime() < deadline) {
                try {
                    process.waitFor(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
                } catch (InterruptedException failure) {
                    interrupted = true;
                }
            }
            assertFalse("Owned fixture process could not be reaped", process.isAlive());
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private static void deleteTree(Path root) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attributes)
                    throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult postVisitDirectory(Path directory, IOException failure)
                    throws IOException {
                if (failure != null) throw failure;
                Files.delete(directory);
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
