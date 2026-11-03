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

        if (program == null) {
            System.out.println("[GhydraMCP] HEADLESS FAILED: no program was imported");
            return;
        }

        int port = portFromArgs();
        Map<Integer, Object> instances = new ConcurrentHashMap<>();

        GhydraServerFactory.Handle handle =
            GhydraServerFactory.startHeadless(program, project, port, instances, true);
        // The registry of the instances is read by the /instances route, and
        // it knows two things: the plugin of a CodeBrowser, and a map that
        // carries the snapshot of the program. A headless run has no plugin
        // - so the snapshot is what is registered, and the file, the
        // project, the executable, the architecture and the image base are
        // there for the clients that pick an instance.
        instances.put(port, snapshot(program, project, port));

        System.out.println("[GhidraMCP] HEADLESS READY port=" + port
            + " program=" + program.getName()
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
        while (!stop.exists()) {
            Thread.sleep(500);
        }
        stop.delete();

        System.out.println("[GhydraMCP] HEADLESS STOPPED port=" + port);
        System.out.flush();
    }

    /** What /instances says about this run. */
    private Map<String, Object> snapshot(Program program, Project project, int port) {
        Map<String, Object> snapshot = new java.util.LinkedHashMap<>();
        snapshot.put("port", port);
        snapshot.put("url", "http://localhost:" + port);
        snapshot.put("isBaseInstance", true);
        snapshot.put("toolName", null);
        snapshot.put("project", project != null ? project.getName() : null);
        snapshot.put("file", program.getName());
        snapshot.put("executable", program.getExecutablePath());
        snapshot.put("architecture", program.getLanguageID().getIdAsString());
        snapshot.put("imageBase", program.getImageBase().toString());
        return snapshot;
    }

    /**
     * The file the launcher leaves behind to stop the run.
     *
     * It sits with the other state of the launcher, in the home directory of
     * the user that runs the analysis.
     */
    private java.io.File stopFile(int port) {
        String home = System.getProperty("user.home", ".");
        java.io.File dir = new java.io.File(home, ".ghidra");
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
