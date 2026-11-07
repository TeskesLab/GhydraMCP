package eu.starsong.ghidra.service;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

/** Language selection contracts that do not require a running Ghidra application. */
public class ScriptServiceTest {

    @Test
    public void filenameInfersLanguageOnlyWhenLanguageIsAbsent() {
        assertEquals("python", ScriptService.normalizeLanguage(null, "probe.py"));
        assertEquals("python", ScriptService.normalizeLanguage(" ", "C:\\work\\probe.PY"));
        assertEquals("java", ScriptService.normalizeLanguage(null, "MassRename.java"));
    }

    @Test
    public void explicitLanguageWinsOverConflictingFilename() {
        for (String language : new String[] {"python", "python3", "py", "PyGhidra"}) {
            assertEquals("python", ScriptService.normalizeLanguage(language, "Thing.java"));
        }
        assertEquals("java", ScriptService.normalizeLanguage(" JAVA ", "probe.py"));
    }

    @Test
    public void unsupportedExplicitLanguageCannotFallBackToRecognizedFilename() {
        for (String filename : new String[] {"probe.py", "Thing.java", null}) {
            assertThrows(IllegalArgumentException.class,
                () -> ScriptService.normalizeLanguage("ruby", filename));
        }
    }
}
