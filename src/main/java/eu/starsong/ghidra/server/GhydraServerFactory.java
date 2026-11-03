package eu.starsong.ghidra.server;

import eu.starsong.ghidra.resource.*;
import eu.starsong.ghidra.service.DecompilerService;
import eu.starsong.ghidra.service.FunctionService;
import eu.starsong.ghidra.service.ScalarService;
import eu.starsong.ghidra.service.VariableService;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.Map;

/**
 * Builds the HTTP server and registers every resource.
 *
 * <p>The CodeBrowser plugin and the headless runner start the same server: the
 * resources, the decompiler service and the middleware are the same, and only
 * what is behind them differs — a CodeBrowser with its ProgramManager, or a
 * headless run with one fixed program and one fixed project.
 *
 * <p>Keeping the list here is what makes the two paths equal. When a resource
 * is added to the plugin and not here, the headless instance answers 404 for
 * an endpoint the GUI one serves.
 */
public final class GhydraServerFactory {

    private GhydraServerFactory() {
    }

    /** A started server, with everything it owns. */
    public record Handle(GhydraServer server, DecompilerService decompilerService) {

        public int port() {
            return server.port();
        }

        /**
         * Stop the server and release what it owns.
         *
         * <p>The decompiler service keeps a native decompiler process alive and
         * a listener on the program, so it has to be disposed with the server.
         */
        public void stop() {
            server.stop();
            if (decompilerService != null) {
                decompilerService.dispose();
            }
        }
    }

    /**
     * Start a server for a CodeBrowser instance.
     *
     * @param tool the CodeBrowser's tool: the program and the project are read
     *             from it, and the UI endpoints need it
     */
    public static Handle startForTool(PluginTool tool, int port,
            Map<Integer, Object> activeInstances, boolean isBaseInstance) {
        return start(tool, null, null, port, activeInstances, isBaseInstance);
    }

    /**
     * Start a server for an instance that runs without a CodeBrowser.
     *
     * @param program the analysed program: there is no ProgramManager to ask
     * @param project the project the program belongs to
     */
    public static Handle startHeadless(Program program, Project project, int port,
            Map<Integer, Object> activeInstances, boolean isBaseInstance) {
        return start(null, program, project, port, activeInstances, isBaseInstance);
    }

    private static Handle start(PluginTool tool, Program program, Project project, int port,
            Map<Integer, Object> activeInstances, boolean isBaseInstance) {
        GhydraServer server = new GhydraServer(tool, port, activeInstances, isBaseInstance, program, project);

        // One shared decompiler service per instance: one native decompiler
        // process + one program listener, disposed with the server.
        var functionService = new FunctionService();
        var decompilerService = new DecompilerService(functionService);

        server.register(
            new RootResource(isBaseInstance),
            new FunctionResource(functionService, decompilerService),
            new SymbolResource(),
            new DataResource(),
            new MemoryResource(),
            new SegmentResource(),
            new XrefResource(),
            new ProgramResource(),
            new InstanceResource(),
            new AnalysisResource(),
            new StructResource(),
            new DataTypeResource(),
            new ScalarResource(new ScalarService()),
            new VariableResource(new VariableService(decompilerService)),
            new ClassResource(),
            new NamespaceResource(),
            new ProjectResource(),
            new UiResource(),
            new ScriptResource(),
            new RawImageResource(),
            new DevResource(port)
        );

        server.start();
        return new Handle(server, decompilerService);
    }
}
