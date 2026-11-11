package eu.starsong.ghidra;

import eu.starsong.ghidra.api.ApiConstants;
import eu.starsong.ghidra.resource.*;
import eu.starsong.ghidra.server.GhydraServer;
import eu.starsong.ghidra.server.GhydraServerFactory;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * GhydraMCP Plugin - Exposes Ghidra functionality via REST API.
 *
 * This is the new Javalin-based implementation of the plugin.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Ghidra HATEOAS interface",
    description = "Ghidra HATEOAS interface for all CodeBrowser instances in parallel.",
    servicesRequired = { ProgramManager.class }
)
public class GhydraPlugin extends Plugin implements ApplicationLevelPlugin {

    static {
        // Prints to the Ghidra launcher console before logger init.
        System.err.println("[GhydraPlugin] static init: class loaded from " +
            GhydraPlugin.class.getProtectionDomain().getCodeSource().getLocation());
    }

    public static final Map<Integer, GhydraPlugin> activeInstances = new ConcurrentHashMap<>();
    private static final Object baseInstanceLock = new Object();

    private GhydraServerFactory.Handle handle;
    private int port;
    private boolean isBaseInstance = false;

    public GhydraPlugin(PluginTool tool) {
        super(tool);

        // Probe-and-claim atomically so two concurrently-constructed plugins
        // can't both pick the same free port.
        synchronized (activeInstances) {
            this.port = GhydraServer.findAvailablePort(activeInstances);
            activeInstances.put(port, this);
        }

        synchronized (baseInstanceLock) {
            if (port == ApiConstants.DEFAULT_PORT || activeInstances.get(ApiConstants.DEFAULT_PORT) == null) {
                this.isBaseInstance = true;
                Msg.info(this, "Starting as base instance on port " + port);
            }
        }

        Msg.info(this, "GhydraMCP loaded on port " + port);
        System.out.println("[GhydraMCP] Plugin loaded on port " + port);

        // The flags that turn the guarded endpoints on are read from the
        // system properties and from the environment. A user who sets one and
        // finds the endpoint still refusing needs to see what the plugin saw:
        // the name of the property, the name of the environment variable, and
        // whether the endpoint ended up on.
        Msg.info(this, "GhidraMCP flags: scripts="
            + eu.starsong.ghidra.resource.ScriptResource.scriptsEnabled()
            + " (" + eu.starsong.ghidra.resource.ScriptResource.PROPERTY + "="
            + System.getProperty(eu.starsong.ghidra.resource.ScriptResource.PROPERTY)
            + ", " + eu.starsong.ghidra.resource.ScriptResource.ENV + "="
            + System.getenv(eu.starsong.ghidra.resource.ScriptResource.ENV)
            + "), devShutdown="
            + eu.starsong.ghidra.resource.DevResource.shutdownEnabled()
            + " (" + eu.starsong.ghidra.resource.DevResource.PROPERTY + "="
            + System.getProperty(eu.starsong.ghidra.resource.DevResource.PROPERTY)
            + ", " + eu.starsong.ghidra.resource.DevResource.ENV + "="
            + System.getenv(eu.starsong.ghidra.resource.DevResource.ENV) + ")");

        startServer();
        startServer();
    }

    private void startServer() {
        try {
            handle = GhydraServerFactory.startForTool(tool, port, castActiveInstances(), isBaseInstance);
            System.out.println("[GhydraMCP] HTTP server started on port " + port);

        } catch (Exception e) {
            // Deregister so clients don't discover a registered-but-dead instance,
            // and so the port frees up for a later retry.
            activeInstances.remove(port);
            handle = null;
            Msg.error(this, "Failed to start HTTP server on port " + port + "; instance deregistered", e);
            System.err.println("[GhydraMCP] Failed to start HTTP server: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<Integer, Object> castActiveInstances() {
        return (Map<Integer, Object>) (Map<?, ?>) activeInstances;
    }

    @Override
    public void dispose() {
        // Deregister first so /instances stops advertising a dying server.
        activeInstances.remove(port);
        if (handle != null) {
            handle.stop();
            // Kills the native decompiler process and removes the program listener.
            handle = null;
            System.out.println("[GhydraMCP] HTTP server stopped on port " + port);
        }
        super.dispose();
    }

    public int getPort() {
        return port;
    }

    public boolean isBaseInstance() {
        return isBaseInstance;
    }

    /**
     * Build a metadata snapshot for this instance — what InstanceResource
     * surfaces under /instances so clients can pick the right port without
     * polling /info on every one.
     */
    public Map<String, Object> getInstanceSnapshot() {
        Map<String, Object> snapshot = new java.util.LinkedHashMap<>();
        snapshot.put("port", port);
        snapshot.put("url", "http://localhost:" + port);
        snapshot.put("isBaseInstance", isBaseInstance);
        snapshot.put("headless", false);
        snapshot.put("toolName", tool != null ? tool.getName() : null);

        ghidra.framework.model.Project project = tool != null ? tool.getProject() : null;
        snapshot.put("project", project != null ? project.getName() : null);

        ProgramManager pm = tool != null ? tool.getService(ProgramManager.class) : null;
        ghidra.program.model.listing.Program current = pm != null ? pm.getCurrentProgram() : null;
        if (current != null) {
            snapshot.put("file", current.getName());
            snapshot.put("executable", current.getExecutablePath());
            snapshot.put("architecture", current.getLanguageID().getIdAsString());
            snapshot.put("imageBase", current.getImageBase().toString());
        } else {
            snapshot.put("file", null);
        }
        return snapshot;
    }
}
