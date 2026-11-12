package ghidra.features.bsim.query;

/** Deterministic native factory surrogate, with no network or authentication UI. */
public class BSimClientFactory {
    public static BSimServerInfo selected;
    public static boolean asynchronous;
    public static boolean initializeResult = true;
    public static boolean throwOnInitialize;
    public static String connectionType = "SSL_Authentication";
    public static RemoteClient lastClient;
    public static int builds;

    public static FunctionDatabase buildClient(BSimServerInfo info, boolean async) {
        selected = info;
        asynchronous = async;
        builds++;
        lastClient = new RemoteClient();
        return lastClient;
    }

    public static class RemoteClient implements FunctionDatabase {
        public int closes;
        public boolean initialize() {
            if (throwOnInitialize) {
                throw new IllegalStateException("postgresql://private-user:secret@private-host/db");
            }
            return initializeResult;
        }
        public String getConnectionType() { return connectionType; }
        public String getLastError() { return "secret@private-host database password=secret"; }
        public void close() { closes++; }
    }
}
