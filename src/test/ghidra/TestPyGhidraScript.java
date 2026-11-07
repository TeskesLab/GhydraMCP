// Live regression for ad-hoc Java and genuine Python 3 execution.
// Run as a postScript with the extension installed and a current program.
// Python cases require Ghidra launched through PyGhidra; an absent/uninitialized
// runtime prints SKIP, but any unexpected load or execution failure fails the test.

import eu.starsong.ghidra.service.ScriptService;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.UUID;

public class TestPyGhidraScript extends GhidraScript {
    private static final String PATH_MARKER = "REGRESSION_SOURCE=";
    private final ScriptService service = new ScriptService();

    @Override
    public void run() throws Exception {
        try {
            Class.forName("ghidra.app.script.ScriptControls");
        } catch (ClassNotFoundException legacyGhidra) {
            println("SKIP TestPyGhidraScript: capture assertions require Ghidra 12+");
            return;
        }
        Path directory = GhidraScriptUtil.getUserScriptDirectory().getFile(false).toPath();
        Files.createDirectories(directory);
        testJava(directory);
        testInvalidJava();
        if (!pythonReady(directory)) {
            println("PASS TestPyGhidraScript: Java; SKIP Python 3 (runtime unavailable)");
            return;
        }

        // No @runtime tag: this exercises the service's Python 3 selection even
        // when Jython is also installed and could claim the .py extension.
        String python = "import sys\n"
            + "assert sys.version_info.major == 3, sys.version\n"
            + "print(f'PRINT_PYTHON_{sys.version_info.major}')\n"
            + "println(f'PROGRAM={currentProgram.getName()}')\n"
            + "println('REGRESSION_SOURCE=' + str(getSourceFile().getAbsolutePath()))\n"
            + "args = [str(arg) for arg in getScriptArgs()]\n"
            + "assert args == ['two words', '', 'quote\"value', 'caf\\u00e9'], repr(args)\n"
            + "println(f'ARGS_OK={len(args)}')\n";
        String[] args = {"two words", "", "quote\"value", "caf\u00e9"};

        // Reserve our own existing script atomically; never write a fixed user filename.
        Path sentinel = Files.createTempFile(directory, "PyGhidraRegression_", ".py");
        String original = "# Existing script must survive ad-hoc execution.\n";
        try {
            Files.writeString(sentinel, original);
            ScriptService.RunResult inferred = runAndCheckCleanup(directory, python, args,
                null, sentinel.getFileName().toString());
            requireSuccess(inferred);
            require(inferred.output().contains("PRINT_PYTHON_3"),
                "Python print output missing: " + inferred.output());
            require(inferred.output().contains("PROGRAM=" + currentProgram.getName()),
                "Python currentProgram/println output missing: " + inferred.output());
            require(inferred.output().contains("ARGS_OK=4"),
                "Python arguments/println output missing: " + inferred.output());
            require(Files.exists(sentinel), "Existing Python script was deleted");
            require(Files.readString(sentinel).equals(original), "Existing Python script changed");

            // Explicit language overrides both extension and competing runtime metadata.
            ScriptService.RunResult explicit = runAndCheckCleanup(directory,
                "# @runtime Jython\n" + python, args,
                "python3", "Regression_" + UUID.randomUUID().toString().replace("-", "") + ".java");
            requireSuccess(explicit);
            require(explicit.output().contains("PRINT_PYTHON_3")
                    && explicit.output().contains("ARGS_OK=4"),
                "Explicit Python execution did not capture output/arguments: " + explicit.output());

            String failing = "import sys\nassert sys.version_info.major == 3\n"
                + "println('REGRESSION_SOURCE=' + str(getSourceFile().getAbsolutePath()))\n"
                + "print(f'BEFORE_ERROR_{sys.version_info.major}')\n"
                + "raise RuntimeError('intentional regression failure')\n";
            ScriptService.RunResult failure = runAndCheckCleanup(directory, failing,
                new String[0], "python", sentinel.getFileName().toString());
            require(!failure.success(), "Python exception incorrectly reported success");
            require(failure.error() != null && !failure.error().isBlank(),
                "Python exception did not return an error");
            require(failure.error().contains("intentional regression failure"),
                "Python traceback diagnostic was lost: " + failure.error());
            require(failure.output().contains("BEFORE_ERROR_3"),
                "Output before Python exception was lost: " + failure.output());
            require(Files.exists(sentinel), "Existing Python script was deleted after failed execution");
            require(Files.readString(sentinel).equals(original),
                "Existing Python script changed after failed execution");
        } finally {
            Files.deleteIfExists(sentinel);
        }
        println("PASS TestPyGhidraScript: Java and Python 3");
    }

    private boolean pythonReady(Path directory) throws Exception {
        GhidraScriptProvider python = null;
        for (GhidraScriptProvider provider : GhidraScriptUtil.getProviders()) {
            if (provider.getClass().getName().equals("ghidra.pyghidra.PyGhidraScriptProvider")) {
                python = provider;
                break;
            }
        }
        if (python == null) {
            println("SKIP Python 3: PyGhidra provider is not installed (Jython does not qualify)");
            return false;
        }
        Path probe = Files.createTempFile(directory, "PyGhidraReadiness_", ".py");
        try {
            // Instantiation checks whether PyGhidra's Python-side runner was
            // initialized. Merely registering a .py provider does not establish that.
            python.getScriptInstance(new ResourceFile(probe.toFile()),
                new PrintWriter(new StringWriter()));
            return true;
        } catch (GhidraScriptLoadException e) {
            // Only the provider's documented unavailable-runtime condition is a
            // skip. Syntax, I/O and unexpected runtime errors must remain failures.
            if ("Ghidra was not started with PyGhidra. Python is not available".equals(e.getMessage())) {
                println("SKIP Python 3: Ghidra was not launched through PyGhidra");
                return false;
            }
            throw e;
        } finally {
            Files.deleteIfExists(probe);
        }
    }

    private void testJava(Path directory) throws Exception {
        String className = "JavaRegression_" + UUID.randomUUID().toString().replace("-", "");
        require(!Files.exists(directory.resolve(className + ".java")),
            "Refusing to replace a pre-existing Java script");
        String source = "import ghidra.app.script.GhidraScript;\n"
            + "public class " + className + " extends GhidraScript {\n"
            + " public void run() {\n"
            + "  println(\"REGRESSION_SOURCE=\" + getSourceFile().getAbsolutePath());\n"
            + "  print(\"JAVA_PRINT\"); println(\"_OK\");\n"
            + "  println(\"JAVA_ARG=\" + getScriptArgs()[0]);\n"
            + "  if (getScriptArgs()[0].equals(\"fail\")) throw new IllegalStateException(\"intentional failure\");\n"
            + " }\n}\n";
        Path existing = Files.createFile(directory.resolve(className + ".java"));
        String original = "// Existing Java script\n";
        try {
            Files.writeString(existing, original);
            boolean refused = false;
            try {
                service.runSource(state.getTool(), state.getProject(), currentProgram,
                    source, new String[] {"unused"}, "java", null);
            } catch (RuntimeException expected) {
                refused = true;
            }
            require(refused, "Existing Java script was not refused");
            require(Files.exists(existing) && Files.readString(existing).equals(original),
                "Existing Java script was modified or deleted");
        } finally {
            Files.deleteIfExists(existing);
        }
        // The legacy overload and explicit Java both still execute Java source;
        // the latter must take precedence over a misleading .py filename.
        ScriptService.RunResult legacy = service.runSource(state.getTool(), state.getProject(),
            currentProgram, source, new String[] {"legacy argument"});
        assertSourceRemoved(directory, legacy);
        requireSuccess(legacy);
        require(legacy.output().contains("JAVA_PRINT_OK")
                && legacy.output().contains("JAVA_ARG=legacy argument"),
            "Legacy Java output/arguments missing: " + legacy.output());
        ScriptService.RunResult explicit = runAndCheckCleanup(directory, source,
            new String[] {"explicit argument"}, "java", className + ".py");
        requireSuccess(explicit);
        require(explicit.output().contains("JAVA_ARG=explicit argument"),
            "Explicit Java language did not override filename: " + explicit.output());
        ScriptService.RunResult failure = runAndCheckCleanup(directory, source,
            new String[] {"fail"}, "java", className + ".java");
        require(!failure.success(), "Java exception incorrectly reported success");
        require(failure.error() != null && !failure.error().isBlank(),
            "Java exception did not return an error");
        require(failure.output().contains("JAVA_ARG=fail"),
            "Output before Java exception was lost: " + failure.output());
    }

    private void testInvalidJava() {
        try {
            service.runSource(state.getTool(), state.getProject(), currentProgram,
                "print('not Java')\n", new String[0], "java", null);
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Java source without a GhidraScript class was accepted");
    }

    private ScriptService.RunResult runAndCheckCleanup(Path directory, String source,
            String[] args, String language, String filename) throws Exception {
        ScriptService.RunResult result = service.runSource(state.getTool(), state.getProject(),
            currentProgram, source, args, language, filename);
        assertSourceRemoved(directory, result);
        return result;
    }

    private void assertSourceRemoved(Path directory, ScriptService.RunResult result) throws Exception {
        for (String line : result.output().split("\\R")) {
            if (line.startsWith(PATH_MARKER)) {
                Path source = Path.of(line.substring(PATH_MARKER.length())).toAbsolutePath().normalize();
                Path root = directory.toAbsolutePath().normalize();
                require(source.startsWith(root), "Ad-hoc source escaped user script directory: " + source);
                boolean sourceExists = Files.exists(source);
                boolean temporaryDirectoryExists = !source.getParent().equals(root)
                    && Files.exists(source.getParent());
                // Report leaks, but still clean up this invocation's own files.
                try {
                    require(!sourceExists, "Ad-hoc source was not removed: " + source);
                    require(!temporaryDirectoryExists,
                        "Ad-hoc temporary directory was not removed: " + source.getParent());
                } finally {
                    Files.deleteIfExists(source);
                    if (!source.getParent().equals(root) && Files.exists(source.getParent())) {
                        try (var paths = Files.walk(source.getParent())) {
                            var remaining = paths.sorted(Comparator.reverseOrder()).iterator();
                            while (remaining.hasNext()) {
                                Files.deleteIfExists(remaining.next());
                            }
                        }
                    }
                }
                return;
            }
        }
        throw new AssertionError("Script never reported its source path: " + result);
    }

    private void requireSuccess(ScriptService.RunResult result) {
        require(result.success(), "Script execution failed: " + result);
        require(result.error() == null, "Successful script returned an error: " + result);
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
