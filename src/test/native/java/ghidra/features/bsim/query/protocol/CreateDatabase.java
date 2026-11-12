package ghidra.features.bsim.query.protocol;

import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.DatabaseInformation;

/** Counts creation attempts; remote regression tests require this count to stay zero. */
public class CreateDatabase {
    public static int executions;
    public DatabaseInformation info;
    public String config_template;
    public Object execute(FunctionDatabase database) { executions++; return new Object(); }
}
