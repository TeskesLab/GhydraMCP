package eu.starsong.ghidra.util;

import ghidra.util.Swing;
import ghidra.util.exception.UnableToSwingException;

import java.util.concurrent.TimeUnit;
import javax.swing.SwingUtilities;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Marshals read-only program-database access onto the Swing/EDT thread.
 *
 * <p>Ghidra's database is single-threaded by convention: writes go through the EDT
 * (see {@link TransactionHelper}) and the UI reads/renders on the EDT. Individual DB
 * calls self-lock via the internal {@code ghidra.util.Lock}, but compound reads -
 * iterating {@code getFunctions(true)}, walking the listing, scanning symbols/xrefs -
 * release that lock between records. A pool-thread iteration interleaving with EDT
 * activity leaves buffer nodes checked out and throws {@code IOException: Locked buffer}.
 *
 * <p>Running the traversal on the EDT via {@link Swing#runNow} removes the interleaving.
 * {@code runNow} executes inline when already on the EDT, so this helper is reentrant and
 * safe to nest. Long, self-managed operations (the decompiler's {@code DecompInterface},
 * {@code AutoAnalysisManager}) handle their own program access and must NOT be wrapped -
 * doing so would freeze the UI for their full duration.
 */
public final class GhidraSwing {

    private static final long READ_TIMEOUT_SECONDS = Long.getLong("ghidra.mcp.read.timeout", 900);

    private GhidraSwing() {
    }

    @FunctionalInterface
    public interface ReadOperation<T> {
        T get() throws Exception;
    }

    /** Serializes on the actual EDT even when native Ghidra Swing dispatch is headless-inline. */
    public static void runNow(Runnable operation, long timeout, TimeUnit unit)
            throws UnableToSwingException {
        if (SwingUtilities.isEventDispatchThread()) {
            Swing.runNow(operation, timeout, unit);
            return;
        }
        AtomicBoolean pending = new AtomicBoolean(true);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<Void> finished = new CompletableFuture<>();
        SwingUtilities.invokeLater(() -> {
            if (!pending.compareAndSet(true, false)) return;
            started.countDown();
            try {
                Swing.runNow(operation, timeout, unit);
                finished.complete(null);
            } catch (Throwable e) {
                finished.completeExceptionally(e);
            }
        });
        try {
            if (!started.await(timeout, unit) && pending.compareAndSet(true, false)) {
                throw new UnableToSwingException("Timed out waiting to reach the Swing thread");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (pending.compareAndSet(true, false)) {
                throw new UnableToSwingException("Interrupted waiting to reach the Swing thread");
            }
        }
        // A started callback may own a transaction or consumer: never abandon it.
        join(finished);
    }

    /** Acquires/releases native resources without abandoning a callback on interruption/timeout. */
    public static <T> T runUninterruptibly(Supplier<T> operation) {
        if (SwingUtilities.isEventDispatchThread()) return operation.get();
        CompletableFuture<T> finished = new CompletableFuture<>();
        SwingUtilities.invokeLater(() -> {
            try { finished.complete(operation.get()); }
            catch (Throwable e) { finished.completeExceptionally(e); }
        });
        return join(finished);
    }

    private static <T> T join(CompletableFuture<T> finished) {
        try {
            return finished.join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof RuntimeException runtime) throw runtime;
            if (e.getCause() instanceof Error error) throw error;
            throw e;
        }
    }

    /**
     * Runs a read-only operation on the Swing thread and returns its result.
     *
     * @throws ReadException if the operation throws, or the EDT cannot be reached in time
     */
    public static <T> T runRead(ReadOperation<T> operation) {
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<RuntimeException> runtimeError = new AtomicReference<>();
        AtomicReference<Throwable> otherError = new AtomicReference<>();

        Runnable task = () -> {
            try {
                result.set(operation.get());
            } catch (RuntimeException e) {
                runtimeError.set(e);
            } catch (Throwable t) {
                // Checked exceptions AND Errors. Notably StackOverflowError: Ghidra's own
                // pointer-label resolution recurses without bound on a self-referential
                // pointer (getLabelString -> getDynamicName -> getDefaultLabelPrefix -> ...).
                // Capturing it here fails the request cleanly instead of letting the Error
                // escape onto the EDT and into Ghidra's uncaught-exception handler.
                otherError.set(t);
            }
        };

        try {
            runNow(task, READ_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (UnableToSwingException e) {
            throw new ReadException(
                "Timed out after " + READ_TIMEOUT_SECONDS + "s waiting for the Swing thread", e);
        }

        if (runtimeError.get() != null) {
            throw runtimeError.get();
        }
        if (otherError.get() != null) {
            Throwable t = otherError.get();
            String msg = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
            throw new ReadException(msg, t);
        }
        return result.get();
    }

    /**
     * Runs a read-only operation on the Swing thread with no return value.
     */
    public static void runRead(Runnable operation) {
        runRead(() -> {
            operation.run();
            return null;
        });
    }

    public static class ReadException extends RuntimeException {
        public ReadException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
