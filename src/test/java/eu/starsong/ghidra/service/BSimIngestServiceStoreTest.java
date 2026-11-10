package eu.starsong.ghidra.service;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * When a stored ingest may be called complete.
 *
 * <p>BSim refuses a second insert of the same executable by fingerprint, and
 * it refuses it <em>before</em> it inserts any function. So an executable
 * that was ingested with a cap stays a partial corpus, and the later ingest
 * that was supposed to complete it is answered with "already ingested" while
 * the database still holds the first subset. The stored set is counted and
 * compared with what the program can produce, and only a store that covers
 * the program is a success.
 */
public class BSimIngestServiceStoreTest {

    @Test
    public void a_store_that_covers_the_program_is_complete() {
        assertTrue(BSimIngestService.storedIngestIsComplete(1000, 1000));
        assertTrue(BSimIngestService.storedIngestIsComplete(1001, 1000));
    }

    @Test
    public void a_store_that_holds_a_subset_is_not_complete() {
        // The defect: the first ingest stored one function, the second one
        // cannot add the rest.
        assertFalse(BSimIngestService.storedIngestIsComplete(1, 1000));
        assertFalse(BSimIngestService.storedIngestIsComplete(999, 1000));
    }

    @Test
    public void a_store_that_could_not_be_counted_is_never_complete() {
        assertFalse(BSimIngestService.storedIngestIsComplete(-1, 1000));
        assertFalse(BSimIngestService.storedIngestIsComplete(1000, -1));
    }
}
