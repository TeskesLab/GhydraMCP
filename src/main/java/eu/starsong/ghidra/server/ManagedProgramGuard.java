package eu.starsong.ghidra.server;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.service.RepositoryService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.awt.Dialog;
import java.awt.Window;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/** Validates live native ownership at the mutation's Swing dispatch point, not at request entry. */
public final class ManagedProgramGuard {
    private static final Set<Program> READ_ONLY = Collections.synchronizedSet(
        Collections.newSetFromMap(new IdentityHashMap<>()));

    /** Follow a read-only view through other GUI consumers until its native close. */
    public static void registerReadOnly(Program program) {
        if (READ_ONLY.add(program)) {
            program.addCloseListener(closed -> READ_ONLY.remove(closed));
        }
    }

    private ManagedProgramGuard() {}

    public static boolean isManaged(Program program) {
        if (READ_ONLY.contains(program)) return true;
        for (Object consumer : program.getConsumerList()) {
            if (consumer instanceof RepositoryService) return true;
        }
        return false;
    }

    /** Returns false for ordinary programs, whose existing transaction/save semantics are unchanged. */
    public static boolean validateMutation(Program program) {
        return validate(program, true);
    }

    /** A no-change save still validates ownership, but does not require write permission. */
    public static boolean validateSave(Program program) {
        return validate(program, program.isChanged());
    }

    private static boolean validate(Program program, boolean writing) {
        var consumers = program.getConsumerList();
        boolean readOnly = READ_ONLY.contains(program);
        boolean managed = readOnly;
        for (Object consumer : consumers) {
            if (consumer instanceof RepositoryService) {
                managed = true;
                break;
            }
        }
        if (!managed) return false;
        if (program.isClosed()) throw conflict("Repository program is closed");

        boolean owner = false;
        boolean gui = false;
        for (Object consumer : consumers) {
            if (consumer instanceof PluginTool tool) {
                gui = true;
                ProgramManager manager = tool.getService(ProgramManager.class);
                if (manager != null) {
                    for (Program open : manager.getAllOpenPrograms()) {
                        if (open == program) owner = true;
                    }
                }
            } else if (consumer instanceof ActiveProgram active && active.program() == program) {
                owner = true;
            }
        }
        if (!owner) throw conflict("Repository program is no longer actively open");
        // Native read-only compatibility copies may still report isChangeable=true.
        if (writing && (readOnly || !program.isChangeable() || program.getDomainFile().isReadOnly())) {
            throw new ConnectionException("REPOSITORY_READ_ONLY", 403, "Repository program is read-only");
        }
        if (gui) {
            for (Window window : Window.getWindows()) {
                if (window instanceof Dialog dialog && dialog.isModal() && dialog.isVisible()) {
                    throw conflict("Finish the open modal dialog before modifying a repository program");
                }
            }
        }
        // Native locks are reference-counted; startTransaction retries indefinitely while locked.
        if (program.isLocked()) throw conflict("Repository program is locked by another operation");
        return true;
    }

    private static ConnectionException conflict(String message) {
        return new ConnectionException("REPOSITORY_CONFLICT", 409, message);
    }
}
