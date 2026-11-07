package eu.starsong.ghidra.util;

/**
 * The running Ghidra's API does not match the one the extension was compiled against.
 *
 * <p>The usual cause is a {@link NoSuchMethodError} from a call site whose JVM
 * descriptor names a return type that only exists in the other series (for
 * example {@code DataTypeComponent.setFieldName}: {@code void} in 11.x/12.0-12.1,
 * {@code DataTypeComponent} in 12.2). An {@code Error} is not an
 * {@code Exception}, so it used to escape {@code TransactionHelper}, the
 * resource's {@code catch (Exception)} and Javalin's exception handlers (which
 * are bounded by {@code Exception}) — the client got a 500 with an empty body
 * and nothing reached the log.
 *
 * <p>Converting it to this unchecked exception lets Javalin answer with a
 * structured {@code INCOMPATIBLE_GHIDRA_BUILD} error and an actionable remedy.
 */
public class IncompatibleGhidraBuildException extends RuntimeException {

    public IncompatibleGhidraBuildException(String message) {
        super(message);
    }

    public IncompatibleGhidraBuildException(String message, Throwable cause) {
        super(message, cause);
    }
}
