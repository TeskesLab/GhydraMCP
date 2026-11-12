package ghidra.features.bsim.query;

import java.net.URL;

/** Test-only native API surrogate; never connects to a service. */
public class BSimServerInfo {
    public enum DBType { postgres, elastic, file }
    public final DBType type;
    public final String username;
    public final String host;
    public final int port;
    public final String database;

    public BSimServerInfo(String database) {
        this(DBType.file, null, null, -1, database);
    }

    public BSimServerInfo(URL url) {
        this("postgresql".equals(url.getProtocol()) ? DBType.postgres : DBType.elastic,
            null, url.getHost(), url.getPort(), url.getPath());
    }

    public BSimServerInfo(DBType type, String username, String host, int port, String database) {
        this.type = type;
        this.username = username;
        this.host = host;
        this.port = port;
        this.database = database;
    }
}
