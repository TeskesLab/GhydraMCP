package eu.starsong.ghidra.service;

import static org.junit.Assert.*;
import java.io.File;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.Test;

/** Keep native BSim protocol classes ahead of this suite's intentional connection surrogates. */
public class BSimMetadataFilterIsolationTest {
    @Test public void realNativeMetadataFilters() throws Exception {
        String install = System.getProperty("ghydra.test.ghidraHome");
        String nativeBsim = Path.of(install, "Ghidra", "Features", "BSim", "lib", "BSim.jar").toString();
        String classpath = nativeBsim + File.pathSeparator + System.getProperty("java.class.path");
        var process = new ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.awt.headless=true", "-Duser.home=" + System.getProperty("user.home"),
            "-cp", classpath, BSimMetadataFilterTest.class.getName(), install)
            .inheritIO().start();
        try {
            assertTrue("native metadata regression timed out", process.waitFor(90, TimeUnit.SECONDS));
            assertEquals("native metadata regressions failed", 0, process.exitValue());
        } finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }
}
