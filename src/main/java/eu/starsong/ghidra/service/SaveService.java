package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.server.ManagedProgramGuard;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.ArrayList;
import java.util.List;

/**
 * Persist open programs to the project (Ghidra's "Save").
 *
 * <p>Disk I/O runs off the EDT. Managed GUI saves use Ghidra's modal task pattern to
 * prevent interactive transactions from blocking the EDT on the save's modification lock.
 */
public class SaveService {

    /** Outcome of saving one program. */
    public record SaveResult(String program, boolean saved, String detail) {
    }

    /** Save one program if it has unsaved changes; a no-op (saved=false) when it doesn't. */
    public SaveResult save(Program program) {
        if (program == null) {
            throw new IllegalArgumentException("No program is currently loaded");
        }
        boolean calledOnEdt = SwingUtilities.isEventDispatchThread();
        SaveLease lease = ManagedProgramGuard.isManaged(program)
            ? GhidraSwing.runUninterruptibly(() -> prepareManagedSave(program, calledOnEdt)) : null;
        if (lease != null) {
            if (lease.file == null) return new SaveResult(lease.name, false, "no unsaved changes");
            if (lease.savedOnGui) return new SaveResult(lease.name, true, "saved");
            try {
                // The pin keeps the database alive if the GUI closes it while this I/O runs.
                // Our lock prevents further edits, not other native saves: native save() nests
                // reference-counted locks and serializes the database write itself.
                if (lease.file.isReadOnly()) {
                    throw new RuntimeException("Program '" + lease.name + "' is read-only");
                }
                lease.file.save(TaskMonitor.DUMMY);
                return new SaveResult(lease.name, true, "saved");
            } catch (Exception e) {
                throw new RuntimeException("Failed to save '" + lease.name + "': " + e.getMessage(), e);
            } finally {
                GhidraSwing.runUninterruptibly(() -> {
                    releaseSave(program, lease);
                    return null;
                });
            }
        }
        String name = program.getName();
        if (!program.isChanged()) {
            return new SaveResult(name, false, "no unsaved changes");
        }
        DomainFile df = program.getDomainFile();
        if (df == null || df.isReadOnly()) {
            throw new RuntimeException("Program '" + name + "' is read-only or not backed by a project file");
        }
        try {
            df.save(TaskMonitor.DUMMY);
            return new SaveResult(name, true, "saved");
        } catch (Exception e) {
            throw new RuntimeException("Failed to save '" + name + "': " + e.getMessage(), e);
        }
    }

    private static SaveLease prepareManagedSave(Program program, boolean calledOnEdt) {
        PluginTool saveTool = null;
        for (Object consumer : program.getConsumerList()) {
            if (!(consumer instanceof PluginTool tool)) continue;
            ProgramManager manager = tool.getService(ProgramManager.class);
            if (manager == null) continue;
            for (Program open : manager.getAllOpenPrograms()) {
                if (open == program) saveTool = tool;
            }
        }
        SaveLease lease = acquireManagedSave(program, calledOnEdt);
        if (lease == null || lease.file == null || saveTool == null) return lease;
        try {
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Runnable task = () -> {
                try {
                    if (lease.file.isReadOnly()) throw new IOException("Program is read-only");
                    lease.file.save(TaskMonitor.DUMMY);
                } catch (Throwable e) {
                    failure.set(e);
                }
            };
            // Launch before yielding this EDT acquisition callback. Native TaskLauncher
            // disables GUI input while its worker saves; a bare native lock does not.
            try {
                // Task lives in a native module absent from the baseline compile jars.
                // Reflect only this public Runnable overload; it is non-cancellable,
                // off-EDT, modal, and returns only after its worker has completed.
                Class.forName("ghidra.util.task.TaskLauncher")
                    .getMethod("launchModal", String.class, Runnable.class)
                    .invoke(null, "Save repository program", task);
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException("Native modal repository save is unavailable", e);
            }
            if (failure.get() instanceof Error error) throw error;
            if (failure.get() != null) {
                throw new RuntimeException("Failed to save '" + lease.name + "'", failure.get());
            }
            lease.savedOnGui = true;
            return lease;
        } finally {
            releaseSave(program, lease);
        }
    }

    private static void releaseSave(Program program, SaveLease lease) {
        try { program.unlock(); }
        finally { program.release(lease); }
    }

    private static SaveLease acquireManagedSave(Program program, boolean calledOnEdt) {
        if (!ManagedProgramGuard.validateSave(program)) return null;
        if (calledOnEdt) {
            throw conflict("Repository saves must run off the Swing thread");
        }
        String name = program.getName();
        if (!program.isChanged()) return new SaveLease(name, null);
        DomainFile file = program.getDomainFile();
        if (file == null) {
            throw new RuntimeException("Program '" + name + "' is not backed by a project file");
        }
        SaveLease lease = new SaveLease(name, file);
        if (!program.addConsumer(lease)) throw conflict("Repository program is closed");
        boolean locked = false;
        try {
            // validateMutation rejected existing locks. Native lock() alone is not exclusive.
            locked = program.lock("HTTP repository save");
            if (!locked) throw conflict("Repository program has an active transaction");
            return lease;
        } finally {
            if (!locked) program.release(lease);
        }
    }

    private static final class SaveLease {
        final String name;
        final DomainFile file;
        boolean savedOnGui;
        SaveLease(String name, DomainFile file) {
            this.name = name;
            this.file = file;
        }
    }

    private static ConnectionException conflict(String message) {
        return new ConnectionException("REPOSITORY_CONFLICT", 409, message);
    }


    /** Save every open program that has unsaved changes. */
    public List<SaveResult> saveAllChanged(PluginTool tool) {
        return saveAllChanged(tool, null);
    }

    /**
     * Save every open program that has unsaved changes.
     *
     * @param fallback the program to save when there is no CodeBrowser to ask
     *                 for the open ones. A headless instance has exactly one
     *                 program, and saving it is what makes the analysis
     *                 outlive the run.
     */
    public List<SaveResult> saveAllChanged(PluginTool tool, Program fallback) {
        List<SaveResult> results = new ArrayList<>();
        if (tool == null) {
            if (fallback != null && fallback.isChanged()) {
                results.add(save(fallback));
            }
            return results;
        }
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return results;
        }
        for (Program p : pm.getAllOpenPrograms()) {
            if (p.isChanged()) {
                results.add(save(p));
            }
        }
        return results;
    }
}
