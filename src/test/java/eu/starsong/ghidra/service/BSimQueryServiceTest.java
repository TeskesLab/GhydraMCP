package eu.starsong.ghidra.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


import org.junit.Test;

/**
 * The executable filter that narrows a query to one executable.
 *
 * <p>The filter is the answer to a defect the review named: a comparison asked
 * BSim for five matches <b>across the whole corpus</b> and only afterwards
 * looked for the ones of the wanted executable. When the five best matches
 * belonged to other binaries, the wanted pair was never seen and the function
 * was reported as "not found". The filter travels inside the query now, so the
 * limit is spent on the matches of that executable.
 *
 * <p>What is tested here is the part that does not need a database: that the
 * filter <b>degrades</b> instead of failing, and says why. A build without the
 * BSim filter API, a database that cannot be read, an executable the database
 * does not hold — none of them may turn the comparison into an error, and each
 * has to leave a reason behind. The filter's own attachment to the query is
 * reflective and needs the BSim jar, which this build does not carry; that
 * path was checked against the real jar's signatures instead.
 */
public class BSimQueryServiceTest {

    @Test
    public void without_a_database_the_filter_is_not_applied_and_says_why() {
        // No `-Dghidra.bsim.database` and no `GHYDRA_BSIM_DATABASE` in this JVM.
        assumeNoDatabase();
        BSimQueryService.ExecutableFilter filter =
            BSimQueryService.executableFilter("cmd.exe");
        assertNotNull(filter);
        assertFalse(filter.isApplied());
        assertTrue(filter.reason().contains("no signature database"));
    }

    @Test
    public void an_unknown_executable_is_not_a_false_claim() {
        assumeNoDatabase();
        BSimQueryService.ExecutableFilter filter =
            BSimQueryService.executableFilter("cmd.exe");
        // The database could not be asked, so nothing is claimed about it:
        // null says "unknown", where false would say "the database does not
        // hold it" — a claim nobody made.
        assertNull(filter.found());
    }

    @Test
    public void a_filter_that_could_not_be_built_is_not_applied() {
        BSimQueryService.ExecutableFilter filter =
            new BSimQueryService.ExecutableFilter(null, "no filter here", null);
        assertFalse(filter.isApplied());
        assertEquals("no filter here", filter.reason());
        assertNull(filter.found());
    }

    @Test
    public void a_filter_that_was_disabled_reports_why() {
        BSimQueryService.ExecutableFilter filter =
            new BSimQueryService.ExecutableFilter(new Object(), null, Boolean.TRUE);
        assertTrue(filter.isApplied());
        filter.disable("the BSim query has no filter field");
        assertFalse(filter.isApplied());
        assertEquals("the BSim query has no filter field", filter.reason());
    }

    @Test
    public void a_filter_with_a_reason_never_claims_to_be_applied() {
        BSimQueryService.ExecutableFilter filter =
            new BSimQueryService.ExecutableFilter(new Object(), "a reason", null);
        assertFalse(filter.isApplied());
        assertEquals("a reason", filter.reason());
    }

    /** The filter is built from the database, so the test needs none. */
    private static void assumeNoDatabase() {
        String property = System.getProperty(BSimService.PROPERTY_DATABASE);
        String environment = System.getenv(BSimService.ENV_DATABASE);
        assertNull("this test needs no database configured", property);
        assertNull("this test needs no database configured", environment);
    }
}
