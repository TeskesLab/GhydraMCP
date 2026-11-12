package eu.starsong.ghidra.server;

import eu.starsong.ghidra.connection.ConnectionException;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;

/** Per-server headless selection. The analyzer owns the initial program; we own later selections. */
final class ActiveProgram implements AutoCloseable {
    private final Program initialProgram;
    private final Project initialProject;
    private Program selectedProgram;
    private Project selectedProject;

    ActiveProgram(Program program, Project project) {
        initialProgram = program;
        initialProject = project;
    }

    synchronized Program program() {
        return selectedProgram == null ? initialProgram : selectedProgram;
    }

    synchronized Project project() {
        return selectedProject == null ? initialProject : selectedProject;
    }

    synchronized boolean hasSelection() { return selectedProgram != null; }

    synchronized void activate(Program program, Project project) {
        Program previous = program();
        if (previous == program) return;
        if (previous != null && previous.isChanged()) {
            throw new ConnectionException("REPOSITORY_CONFLICT", 409,
                "Save the active program before opening another repository program.");
        }
        program.addConsumer(this);
        Program owned = selectedProgram;
        selectedProgram = program;
        selectedProject = project;
        if (owned != null) owned.release(this);
    }

    @Override public synchronized void close() {
        if (selectedProgram != null) {
            selectedProgram.release(this);
            selectedProgram = null;
            selectedProject = null;
        }
    }
}
