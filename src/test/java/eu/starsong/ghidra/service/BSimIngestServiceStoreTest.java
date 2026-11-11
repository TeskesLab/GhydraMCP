package eu.starsong.ghidra.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

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
 *
 * <p>The comparison is per executable. {@code DescriptionManager.numFunctions()}
 * counts every description in the manager, and with {@code track_call_graph}
 * Ghidra 12.2's {@code GenSignatures.writeToManager()} adds the
 * imported-library callees to that same manager — so a fully stored program
 * with one function calling an imported {@code Sleep} compared stored=1
 * against expected=2 and was reported as an incomplete ingest.
 */
public class BSimIngestServiceStoreTest {

    /** A stand-in for the BSim executable record. */
    public static class FakeRecord {
        private final String md5;
        private final boolean library;

        FakeRecord(String md5, boolean library) {
            this.md5 = md5;
            this.library = library;
        }

        public boolean isLibrary() {
            return library;
        }

        public String getMd5() {
            return md5;
        }
    }

    /** A stand-in for the BSim function description. */
    public static class FakeDescription {
        private final FakeRecord record;

        FakeDescription(FakeRecord record) {
            this.record = record;
        }

        public FakeRecord getExecutableRecord() {
            return record;
        }
    }

    /**
     * A stand-in for the BSim description manager.
     *
     * <p>The shape is the one the service reads reflectively, so the manager
     * of the BSim build is not needed to test the count.
     */
    public static class FakeManager {
        private final List<FakeDescription> descriptions = new ArrayList<>();
        private final List<FakeRecord> records = new ArrayList<>();

        FakeManager add(FakeRecord record, int functions) {
            records.add(record);
            for (int index = 0; index < functions; index++) {
                descriptions.add(new FakeDescription(record));
            }
            return this;
        }

        public int numFunctions() {
            return descriptions.size();
        }

        public List<FakeRecord> getExecutableRecordSet() {
            return records;
        }

        public Iterator<FakeDescription> listFunctions(FakeRecord record) {
            final Iterator<FakeDescription> all = descriptions.iterator();
            return new Iterator<FakeDescription>() {
                private FakeDescription next;

                @Override
                public boolean hasNext() {
                    while (next == null && all.hasNext()) {
                        FakeDescription candidate = all.next();
                        if (candidate.getExecutableRecord() == record) {
                            next = candidate;
                        }
                    }
                    return next != null;
                }

                @Override
                public FakeDescription next() {
                    if (!hasNext()) {
                        throw new java.util.NoSuchElementException();
                    }
                    FakeDescription answer = next;
                    next = null;
                    return answer;
                }
            };
        }
    }

    private static final String PROGRAM_MD5 = "0123456789abcdef0123456789abcdef";
    private static final String LIBRARY_MD5 = "fedcba9876543210fedcba9876543210";

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

    @Test
    public void the_count_is_of_the_one_executable() {
        // The defect: the manager holds the program's own description and the
        // imported-library callee that `track_call_graph` added, and the total
        // counts both.
        FakeManager manager = new FakeManager()
                .add(new FakeRecord(PROGRAM_MD5, false), 1)
                .add(new FakeRecord(LIBRARY_MD5, true), 1);
        assertEquals(2, manager.numFunctions());
        assertEquals(1, BSimIngestService.describedForExecutable(manager,
            PROGRAM_MD5));
    }

    @Test
    public void the_count_is_the_total_when_the_manager_holds_one_executable() {
        FakeManager manager = new FakeManager()
                .add(new FakeRecord(PROGRAM_MD5, false), 3);
        assertEquals(3, manager.numFunctions());
        assertEquals(3, BSimIngestService.describedForExecutable(manager,
            PROGRAM_MD5));
    }

    @Test
    public void a_manager_that_cannot_be_read_is_never_counted() {
        assertEquals(-1, BSimIngestService.describedForExecutable(null,
            PROGRAM_MD5));
        assertEquals(-1, BSimIngestService.describedForExecutable(
            new FakeManager(), ""));
        assertEquals(-1, BSimIngestService.describedForExecutable(
            new FakeManager(), PROGRAM_MD5));
    }
}
