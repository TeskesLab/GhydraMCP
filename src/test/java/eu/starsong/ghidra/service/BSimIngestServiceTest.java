package eu.starsong.ghidra.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * The ingest cap, pinned.
 *
 * <p>Measured before this test existed: an ingest without a limit scanned every
 * function of the program, and every function is a decompilation — hours inside
 * one request on a large binary, which the client gives up on long before the
 * answer arrives. The default is a cap now, and the cases below are what "the
 * caller did not say", "the caller said everything" and "the caller said more
 * than the maximum" mean.
 */
public class BSimIngestServiceTest {

    @Test
    public void an_absent_limit_is_the_default() {
        assertEquals(BSimIngestService.DEFAULT_MAX_FUNCTIONS,
            BSimIngestService.capFor(-1));
        assertEquals(5_000, BSimIngestService.DEFAULT_MAX_FUNCTIONS);
    }

    @Test
    public void zero_is_an_explicit_everything() {
        assertEquals(Integer.MAX_VALUE, BSimIngestService.capFor(0));
    }

    @Test
    public void a_limit_below_the_maximum_is_kept() {
        assertEquals(1, BSimIngestService.capFor(1));
        assertEquals(7_000, BSimIngestService.capFor(7_000));
    }

    @Test
    public void a_limit_above_the_maximum_is_clamped() {
        assertEquals(BSimIngestService.MAX_FUNCTIONS_LIMIT,
            BSimIngestService.capFor(999_999));
    }

    @Test
    public void the_default_is_below_the_maximum() {
        assertTrue(BSimIngestService.DEFAULT_MAX_FUNCTIONS
            < BSimIngestService.MAX_FUNCTIONS_LIMIT);
    }
}