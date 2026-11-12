package ghidra.features.bsim.query.file;

import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;

/** Local backend surrogate: records dispatch without creating a real database. */
public class H2FileFunctionDatabase implements FunctionDatabase {
    public static BSimServerInfo selected;
    public static int builds;
    public static int closes;
    public H2FileFunctionDatabase(BSimServerInfo info) { selected = info; builds++; }
    public boolean initialize() { return true; }
    public void close() { closes++; }
}
