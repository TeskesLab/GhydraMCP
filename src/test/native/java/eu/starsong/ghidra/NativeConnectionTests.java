package eu.starsong.ghidra;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import java.io.File;
import org.junit.runner.JUnitCore;

/** Full native signatures are needed by proxy fixtures; these are not Maven's pure unit tests. */
public final class NativeConnectionTests {
    public static void main(String[] arguments) throws Exception {
        System.setProperty("ghidra.mcp.bind.host", "127.0.0.1");
        System.setProperty("ghydra.test.ghidraHome", arguments[0]);
        Application.initializeApplication(new GhidraApplicationLayout(new File(arguments[0])),
            new HeadlessGhidraApplicationConfiguration());
        var result = new JUnitCore().run(
            eu.starsong.ghidra.service.BSimRemoteTest.class,
            eu.starsong.ghidra.service.BSimMetadataFilterIsolationTest.class,
            eu.starsong.ghidra.service.BSimMatchServiceTest.class,
            eu.starsong.ghidra.service.BSimReferenceInspectionTest.class,
            eu.starsong.ghidra.service.BSimMatchApplicationTest.class,
            eu.starsong.ghidra.service.RepositoryServiceTest.class,
            eu.starsong.ghidra.server.ManagedProgramGuardTest.class,
            eu.starsong.ghidra.server.HeadlessInstanceTest.class,
            eu.starsong.ghidra.server.NativeRepositoryIntegrationTest.class,
            eu.starsong.ghidra.connection.WorkerAuthenticationTest.class,
            eu.starsong.ghidra.connection.WorkerTLSTest.class,
            eu.starsong.ghidra.connection.WorkerPkiTest.class,
            eu.starsong.ghidra.connection.WorkerHttpTest.class);
        for (var failure : result.getFailures()) {
            System.err.println(failure.getTestHeader());
            failure.getException().printStackTrace();
        }
        System.out.println("Native connection regressions: " + result.getRunCount()
            + " executed, " + result.getFailureCount() + " failed, "
            + result.getIgnoreCount() + " skipped");
        System.exit(result.wasSuccessful() ? 0 : 1);
    }
}
