// Serves the GhidraMCP REST API from a headless Ghidra run.
//
// The CodeBrowser plugin serves the same API from a window a human is
// looking at. This script serves it from a headless run: the binary is
// imported, analysed, and then the API answers for that analysis - with no
// window and nobody watching.
//
// It is meant to be run by the launcher, not by hand:
//
//   analyzeHeadless <project-dir> <project-name> \
//       -import <binary> -postScript GhidraHeadlessServer port=8192
//
// The run stays alive for as long as the server is wanted: the headless
// analyzer waits for this script to return, and it only returns when the
// launcher asks for it.
//
// @category GhydraMCP

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import eu.starsong.ghidra.server.GhydraServerFactory;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;

public class GhidraHeadlessServer extends GhidraScript {

    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        Project project = state.getProject();

        // GhidraScript starts a FlatProgramAPI transaction before run(). Serving
        // for hours inside it prevents HTTP edits from committing or rolling
        // back independently. end() closes only this script's tracked transaction;
        // the framework's final end(true) is then a no-op. Never end arbitrary
        // transactions discovered on the program.
        end(true);

        int port = portFromArgs();
        Map<Integer, Object> instances = new ConcurrentHashMap<>();
        instances.put(port, snapshotFor(port, program, project));

        GhydraServerFactory.Handle handle =
            GhydraServerFactory.startHeadless(program, project, port, instances, true);

        System.out.println("[GhidraMCP] HEADLESS READY port=" + port
            + " program=" + (program != null ? program.getName() : "none")
            + " project=" + (project != null ? project.getName() : "none"));
        System.out.flush();

        // The run has to stay alive for as long as the server is wanted. The
        // launcher stops it: it leaves a stop file behind, and this script
        // returns when it sees the file.
        //
        // Returning is what makes the run end the way it should - the
        // headless analyzer saves the program and closes the project, and the
        // project is left unlocked. Killing the process instead would leave
        // the lock file behind, and the next run would refuse to open the
        // project.
        java.io.File stop = stopFile(port);
        while (true) {
            while (!stop.exists()) Thread.sleep(500);
            stop.delete();
            try {
                handle.stop();
                break;
            } catch (eu.starsong.ghidra.connection.ConnectionException
                    | eu.starsong.ghidra.service.RepositoryService.RepositoryException refused) {
                System.out.println("[GhydraMCP] HEADLESS STOP REFUSED: save work or finish active requests.");
                System.out.flush();
            }
        }
        System.out.println("[GhydraMCP] HTTP server stopped on port " + port);

        System.out.println("[GhydraMCP] HEADLESS STOPPED port=" + port);
        System.out.flush();
    }

    /**
     * What this instance says about itself.
     *
     * <p>There is no CodeBrowser behind a headless run, so there is no
     * plugin to ask. The snapshot is built here and registered instead, so
     * that "/instances" tells the same story about a headless instance as
     * about a windowed one - and says that it is headless, which is what
     * lets a client know that the endpoints that need a window are not
     * there.
     */
    private Map<String, Object> snapshotFor(int port, Program program, Project project) {
        Map<String, Object> snapshot = new java.util.LinkedHashMap<>();
        snapshot.put("port", port);
        snapshot.put("url", "http://localhost:" + port);
        snapshot.put("isBaseInstance", true);
        snapshot.put("headless", true);
        snapshot.put("toolName", null);
        snapshot.put("project", project != null ? project.getName() : null);
        snapshot.put("file", program != null ? program.getName() : null);
        snapshot.put("executable", program != null ? program.getExecutablePath() : null);
        snapshot.put("architecture", program != null ? program.getLanguageID().getIdAsString() : null);
        snapshot.put("imageBase", program != null ? program.getImageBase().toString() : null);
        return snapshot;
    }

    /**
     * The file the launcher leaves behind to stop the run.
     *
     * It sits with the other state of the launcher, in the home directory of
     * the user that runs the analysis.
     */
    private java.io.File stopFile(int port) {
        String configured = System.getenv("GHYDRA_STATE_DIR");
        java.io.File dir = configured == null || configured.isEmpty()
            ? new java.io.File(System.getProperty("user.home", "."), ".ghidra")
            : new java.io.File(configured);
        dir.mkdirs();
        return new java.io.File(dir, "headless-" + port + ".stop");
    }

    /** The port to serve on: "port=8192" in the script arguments. */
    private int portFromArgs() {
        for (String arg : getScriptArgs()) {
            if (arg != null && arg.startsWith("port=")) {
                try {
                    int port = Integer.parseInt(arg.substring("port=".length()).trim());
                    if (port > 0 && port < 65536) {
                        return port;
                    }
                } catch (NumberFormatException e) {
                    // Fall through to the default.
                }
            }
        }
        return 8192;
    }
}
