package eu.starsong.ghidra.service;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

/**
 * Pure-logic tests for ad-hoc script language selection. No live Program and no
 * PyGhidra needed: this is the decision that used to be hardcoded to Java and
 * cost Python 3 its .py extension.
 */
public class ScriptServiceTest {

    @Test
    public void javaIsStillTheDefault() {
        assertEquals("java", ScriptService.normalizeLanguage(null, null));
        assertEquals("java", ScriptService.normalizeLanguage("", ""));
        assertEquals(".java", ScriptService.extensionFor("java"));
    }

    @Test
    public void aPyFilenameSelectsPythonWhenNoLanguageIsGiven() {
        assertEquals("python", ScriptService.normalizeLanguage(null, "probe.py"));
        assertEquals("python", ScriptService.normalizeLanguage("", "C:\\work\\probe.PY"));
        assertEquals(".py", ScriptService.extensionFor("python"));
    }

    @Test
    public void explicitLanguageWinsOverTheFilename() {
        assertEquals("python", ScriptService.normalizeLanguage("python3", "Thing.java"));
        assertEquals("java", ScriptService.normalizeLanguage("java", "probe.py"));
        assertEquals("python", ScriptService.normalizeLanguage("PyGhidra", null));
    }

    @Test
    public void aJavaFilenameSelectsJava() {
        assertEquals("java", ScriptService.normalizeLanguage(null, "MassRename.java"));
    }

    @Test
    public void anUnknownLanguageIsRejectedWithAClearMessage() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> ScriptService.normalizeLanguage("ruby", "probe.rb"));
        assertEquals(true, e.getMessage().contains("java or python"));
    }
}
