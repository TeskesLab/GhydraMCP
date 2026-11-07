package eu.starsong.ghidra.service;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Run Ghidra scripts via the API: list them, run an existing one by name, or run ad-hoc
 * GhidraScript source. The script runs on the calling (HTTP handler) thread, which is off the
 * EDT, matching how Ghidra runs scripts in the background; {@code GhidraScript.execute} manages
 * its own transactions, so DB-modifying scripts work.
 *
 * <p>This is arbitrary code execution; the resource gates it behind an opt-in flag.
 */
public class ScriptService {

    private static final Pattern CLASS_NAME =
        Pattern.compile("class\\s+(\\w+)\\s+extends\\s+GhidraScript");

    /** A script discoverable in the source directories. */
    public record ScriptInfo(String name, String path, String category) {
    }

    /** Outcome of a script run: captured output plus success/error. */
    public record RunResult(String script, String output, boolean success, String error) {
    }

    /** Scripts found in the enabled source directories that have a provider (Java/Python/...). */
    public List<ScriptInfo> list() {
        List<ScriptInfo> out = new ArrayList<>();
        for (ResourceFile dir : GhidraScriptUtil.getEnabledScriptSourceDirectories()) {
            ResourceFile[] files = dir.listFiles();
            if (files == null) {
                continue;
            }
            for (ResourceFile f : files) {
                if (!f.isDirectory() && GhidraScriptUtil.hasScriptProvider(f)) {
                    out.add(new ScriptInfo(f.getName(), f.getAbsolutePath(), dir.getName()));
                }
            }
        }
        return out;
    }

    /** Run an existing script by file name (e.g. "FixupNoReturnFunctionsScript.java"). */
    public RunResult runByName(PluginTool tool, Project project, Program program,
            String name, String[] args) {
        ResourceFile file = GhidraScriptUtil.findScriptByName(name);
        if (file == null) {
            throw new IllegalArgumentException("Script not found: " + name);
        }
        return run(tool, project, program, file, args, null);
    }

    /**
     * Resolve the runtime for an ad-hoc script.
     *
     * <p>An explicit {@code language} wins; a {@code .py} filename is the fallback
     * that preserves the extension of a real source file when none was sent.
     * Java remains the default, preserving v3.0.0 behaviour.
     */
    public static String normalizeLanguage(String language, String filename) {
        if (language != null && !language.isBlank()) {
            String l = language.trim().toLowerCase(Locale.ROOT);
            return switch (l) {
                case "java" -> "java";
                case "python", "python3", "py", "pyghidra" -> "python";
                default -> throw new IllegalArgumentException(
                    "Unsupported script language '" + language + "' (want java or python)");
            };
        }
        if (filename != null && !filename.isBlank()) {
            String lower = filename.toLowerCase(Locale.ROOT);
            if (lower.endsWith(".py")) {
                return "python";
            }
            if (lower.endsWith(".java")) {
                return "java";
            }
        }
        return "java";
    }

    /** The extension the script provider uses to pick Java or PyGhidra. */
    public static String extensionFor(String language) {
        return "python".equals(language) ? ".py" : ".java";
    }

    /**
     * Write ad-hoc source into an isolated temporary directory inside the user
     * script directory, run it, then remove that whole directory. Java source
     * must declare {@code public class &lt;Name&gt; extends GhidraScript};
     * Python 3 source is written as {@code .py} and bound explicitly to the
     * PyGhidra provider.
     *
     * <p>The directory is unique per call. A caller-supplied filename is only a
     * display name: mapping it onto the user script directory would let a
     * request truncate and then delete a real script the user keeps there, and
     * two concurrent ad-hoc runs would overwrite each other's source.
     */
    public RunResult runSource(PluginTool tool, Project project, Program program,
            String source, String[] args) {
        return runSource(tool, project, program, source, args, null, null);
    }

    public RunResult runSource(PluginTool tool, Project project, Program program,
            String source, String[] args, String language, String filename) {
        String lang = normalizeLanguage(language, filename);
        String stem;
        if ("python".equals(lang)) {
            stem = filename != null && !filename.isBlank()
                ? stripExtension(new File(filename).getName())
                : "adhoc_python";
        } else {
            Matcher m = CLASS_NAME.matcher(source);
            if (!m.find()) {
                throw new IllegalArgumentException(
                    "Java source must declare 'public class <Name> extends GhidraScript' with a "
                    + "run() method. For Python 3 pass language=python (or a .py filename).");
            }
            stem = m.group(1);
        }

        File dir = GhidraScriptUtil.getUserScriptDirectory().getFile(false);
        Path tempDir;
        try {
            Files.createDirectories(dir.toPath());
            tempDir = Files.createTempDirectory(dir.toPath(), "ghydra_adhoc_");
        } catch (IOException e) {
            throw new IllegalStateException(
                "Failed to create a temporary script directory: " + e.getMessage(), e);
        }

        File scriptFile = new File(tempDir.toFile(), stem + extensionFor(lang));
        try {
            Files.writeString(scriptFile.toPath(), source);
            return run(tool, project, program, new ResourceFile(scriptFile), args, lang);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to run ad-hoc script: " + e.getMessage(), e);
        } finally {
            deleteTree(tempDir);
        }
    }

    /** Best-effort removal of the temp directory, including compiled .class files. */
    private static void deleteTree(Path root) {
        try (java.util.stream.Stream<Path> walk = Files.walk(root)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // A leftover temp file is harmless; never fail the run for it.
                }
            });
        } catch (IOException ignored) {
            // best effort
        }
    }

    /** A safe file stem: no directories, no punctuation the script loader rejects. */
    private static String stripExtension(String name) {
        int dot = name.lastIndexOf('.');
        String base = dot > 0 ? name.substring(0, dot) : name;
        String safe = base.replaceAll("[^A-Za-z0-9_]", "_");
        return safe.isEmpty() ? "adhoc_python" : safe;
    }

    /**
     * Pick the provider explicitly for Python 3 ad-hoc source.
     *
     * <p>{@code GhidraScriptUtil.getProvider(file)} resolves providers that
     * share an extension from the script's {@code @runtime} metadata. When both
     * Jython and PyGhidra are installed, a bare generated .py file has no such
     * marker, so an explicit {@code language=python} could still be handed to
     * Jython and fail on Python-3-only source. Binding directly to the provider
     * whose runtime is "PyGhidra" makes the selection deterministic. Named
     * scripts (language == null) keep Ghidra's own metadata-based resolution.
     */
    private GhidraScriptProvider providerFor(ResourceFile file, String language) {
        if (!"python".equals(language)) {
            return GhidraScriptUtil.getProvider(file);
        }
        for (GhidraScriptProvider provider : GhidraScriptUtil.getProviders()) {
            String runtime = provider.getRuntimeEnvironmentName();
            if (runtime != null && runtime.toLowerCase(Locale.ROOT).contains("pyghidra")) {
                return provider;
            }
        }
        throw new IllegalArgumentException(
            "No PyGhidra provider is available for ad-hoc Python 3 scripts. "
            + "Launch Ghidra with pyghidraRun, or install the PyGhidra extension "
            + "(Ghidra 11.x+).");
    }

    private RunResult run(PluginTool tool, Project project, Program program,
            ResourceFile file, String[] args, String language) {
        StringWriter sw = new StringWriter();
        PrintWriter writer = new PrintWriter(sw);
        try {
            GhidraScriptProvider provider = providerFor(file, language);
            if (provider == null) {
                String hint = file.getName().toLowerCase(Locale.ROOT).endsWith(".py")
                    ? " Python 3 needs PyGhidra: launch Ghidra with pyghidraRun, or install "
                      + "the PyGhidra extension (Ghidra 11.x+)."
                    : "";
                throw new IllegalArgumentException(
                    "No script provider for " + file.getName() + " (unsupported extension?)." + hint);
            }
            GhidraScript script = provider.getScriptInstance(file, writer);
            if (args != null && args.length > 0) {
                script.setScriptArgs(args);
            }
            ProgramLocation location =
                program != null ? new ProgramLocation(program, program.getMinAddress()) : null;
            // The project comes from the tool when there is one, and from the
            // context when there is not: a headless instance has no tool, but
            // it does have the project the analysed program belongs to, and a
            // script that asks for the current project needs it.
            Project effective = project != null ? project : (tool != null ? tool.getProject() : null);
            GhidraState state = new GhidraState(
                tool, effective, program, location, null, null);
            script.execute(state, TaskMonitor.DUMMY, writer);
            writer.flush();
            return new RunResult(file.getName(), sw.toString(), true, null);
        } catch (Exception e) {
            writer.flush();
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return new RunResult(file.getName(), sw.toString(), false, msg);
        }
    }
}
