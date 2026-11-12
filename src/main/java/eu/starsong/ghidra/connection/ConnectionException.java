package eu.starsong.ghidra.connection;

/** A client-safe connection failure. Native exceptions must not become its cause. */
public final class ConnectionException extends RuntimeException {
    private final String code;
    private final int status;

    public ConnectionException(String code, int status, String message) {
        super(message);
        this.code = code;
        this.status = status;
    }

    public String code() { return code; }
    public int status() { return status; }
}
