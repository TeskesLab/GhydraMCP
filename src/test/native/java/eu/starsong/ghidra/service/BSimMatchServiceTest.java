package eu.starsong.ghidra.service;

import static org.junit.Assert.*;
import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.connection.ConnectionProfiles;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/** Consumer-visible selection lifetime and untrusted repository URL boundaries. */
public class BSimMatchServiceTest {
    private final Object owner = new Object();
    private ProgramDB program;
    private Function function;
    private String previousDirectory;

    @Before public void setup() throws Exception {
        previousDirectory = System.getProperty(ConnectionProfiles.PROPERTY);
        System.clearProperty(ConnectionProfiles.PROPERTY);
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        program = new ProgramDB("selected-target", language, language.getDefaultCompilerSpec(), owner);
        int transaction = program.startTransaction("Create local selection fixture");
        try {
            var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            program.getMemory().createInitializedBlock("text", start, 16, (byte) 0,
                TaskMonitor.DUMMY, false);
            function = program.getFunctionManager().createFunction("source", start,
                new AddressSet(start, start.add(15)), SourceType.USER_DEFINED);
        } finally { program.endTransaction(transaction, true); }
    }

    @After public void cleanup() {
        if (program != null && !program.isClosed()) program.release(owner);
        if (previousDirectory == null) System.clearProperty(ConnectionProfiles.PROPERTY);
        else System.setProperty(ConnectionProfiles.PROPERTY, previousDirectory);
    }

    private String select(BSimMatchService service) {
        Map<String, Object> match = new LinkedHashMap<>();
        match.put("function", "reference");
        match.put("address", "0x2000");
        var rows = new ArrayList<Map<String, Object>>(); rows.add(match);
        Map<String, Object> query = new LinkedHashMap<>();
        query.put("success", true); query.put("matches", rows);
        query.put("source_address", BSimMatchService.qualifiedAddress(function));
        query.put("source_modification", program.getModificationNumber());
        service.register(program, query);
        return (String) match.get("match_id");
    }

    private static void failure(String code, Runnable operation) {
        try { operation.run(); fail("Expected selection refusal"); }
        catch (ConnectionException failure) { assertEquals(code, failure.code()); }
    }

    @Test public void sourceEditInvalidatesTheSelectedMatch() throws Exception {
        var service = new BSimMatchService();
        String id = select(service);
        assertEquals(Boolean.TRUE, service.validate(program, id).get("valid"));
        int transaction = program.startTransaction("Change source after query");
        try { function.setName("changed_source", SourceType.USER_DEFINED); }
        finally { program.endTransaction(transaction, true); }
        failure("BSIM_MATCH_STALE", () -> service.validate(program, id));
    }

    @Test public void differentActiveProgramCannotReplaySelection() {
        var service = new BSimMatchService(); String id = select(service);
        failure("BSIM_MATCH_STALE", () -> service.validate(null, id));
    }

    @Test public void closedSourceCannotReplaySelection() {
        var service = new BSimMatchService(); String id = select(service);
        program.release(owner);
        failure("BSIM_MATCH_STALE", () -> service.validate(program, id));
    }

    @Test public void unknownAndEvictedSelectionsDoNotRequery() {
        var service = new BSimMatchService(); String first = select(service);
        for (int i = 0; i < 256; i++) select(service);
        failure("BSIM_MATCH_UNKNOWN", () -> service.validate(program, first));
        failure("BSIM_MATCH_UNKNOWN", () -> service.validate(program, "not-a-match"));
    }

    @Test public void credentialAndTraversalUrlsCannotLeaveQueryWorker() {
        for (String url : new String[] {"ghidra://user:password@host/repo/program",
                "ghidra://host/repo/program?password=value", "ghidra://host/repo/program#token",
                "ghidra://host/repo/%2e%2e/program", "https://host/repo/program",
                "ghidra://host/repo//program", "ghidra://host/repo/%00program"}) {
            assertNull(BSimMatchService.safeRepositoryUrl(url));
        }
        assertEquals("ghidra://host/repo/path/program",
            BSimMatchService.safeRepositoryUrl("ghidra://host/repo/path/program"));
    }
}
