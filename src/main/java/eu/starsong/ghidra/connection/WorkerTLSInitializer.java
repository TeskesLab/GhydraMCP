package eu.starsong.ghidra.connection;

import ghidra.framework.ModuleInitializer;

/** Install verified TLS before GUI project login can cache native RMI socket factories. */
public final class WorkerTLSInitializer implements ModuleInitializer {
    @Override public String getName() { return "Ghydra credential worker TLS"; }

    @Override public void run() {
        if (!ConnectionProfiles.enabled()) return;
        try {
            WorkerTLS.initialize();
        } catch (Throwable failure) {
            // Ghidra can ignore initializer failures; no native login may proceed insecurely.
            System.err.println("GHYDRA_WORKER_SECURITY_FAILED: verified worker startup failed.");
            System.exit(78);
            throw new ExceptionInInitializerError("Verified worker startup failed");
        }
    }
}
