// Live regression for ad-hoc Python 3 execution (PyGhidra).
//
// v3.0.0's merge removed the /script/execute endpoint; its replacement always
// wrote a .java file and demanded "extends GhidraScript", so Python source
// answered BAD_REQUEST. This test proves a .py source is written with its .py
// extension, selects the PyGhidra provider, runs, and has its output captured.
//
// Runs under analyzeHeadless like the other integration scripts:
//
//   analyzeHeadless <projectDir> PyGhidraTest -import <some-binary> \
//       -scriptPath src/test/ghidra -postScript TestPyGhidraScript
//
// It prints SKIP and returns when this Ghidra has no Python 3 provider, and
// throws on the first real failure so headless reports SCRIPT ERROR (CI gate).

import eu.starsong.ghidra.service.ScriptService;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;

import java.io.File;
import java.nio.file.Files;

public class TestPyGhidraScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Probe first: PyGhidra is optional, so a box without it must not fail.
        File dir = GhidraScriptUtil.getUserScriptDirectory().getFile(false);
        File probe = new File(dir, "TestPyGhidraScript_probe.py");
        try {
            Files.writeString(probe.toPath(), "println('probe')\n");
            if (GhidraScriptUtil.getProvider(new ResourceFile(probe)) == null) {
                println("SKIP TestPyGhidraScript: no Python 3 provider (PyGhidra not available)");
                return;
            }
        } finally {
            probe.delete();
        }

        String python = "println('PYGHIDRA_OK ' + currentProgram.getName())\n";
        ScriptService.RunResult result = new ScriptService().runSource(
            null, null, currentProgram, python, new String[0], "python", "probe.py");

        println("script=" + result.script());
        println("output=" + result.output());
        println("success=" + result.success() + " error=" + result.error());

        if (!result.script().endsWith(".py")) {
            throw new AssertionError(
                "ad-hoc Python source lost its .py extension: " + result.script());
        }
        if (!result.success()) {
            throw new AssertionError("Python 3 script failed: " + result.error());
        }
        if (!result.output().contains("PYGHIDRA_OK")) {
            throw new AssertionError("Python output was not captured: " + result.output());
        }

        // Java support is preserved: a source that is not a GhidraScript class
        // must still be rejected, with a hint pointing at language=python.
        boolean rejected = false;
        try {
            new ScriptService().runSource(null, null, currentProgram,
                "println('not a java class')", new String[0], "java", null);
        } catch (IllegalArgumentException e) {
            rejected = e.getMessage() != null
                && e.getMessage().contains("extends GhidraScript");
        }
        if (!rejected) {
            throw new AssertionError("Java source without a GhidraScript class was not rejected");
        }

        println("PASS TestPyGhidraScript");
    }
}
