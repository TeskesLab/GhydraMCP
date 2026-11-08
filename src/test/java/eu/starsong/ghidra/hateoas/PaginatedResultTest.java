package eu.starsong.ghidra.hateoas;

import eu.starsong.ghidra.server.GhidraContext.Pagination;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The uncounted page (I10).
 *
 * <p>With {@code ?count=false} the server skips the walk that counts matches;
 * the answer has to say so, and it must not present a made-up number as the
 * total. These are pure checks: no Ghidra program and no HTTP server.
 */
public class PaginatedResultTest {

    @Test
    public void a_counted_page_keeps_its_total() {
        PaginatedResult<String> result = new PaginatedResult<>(List.of("a", "b"), 10, 0, 2, "/x");
        Map<String, Object> meta = result.metadata();
        assertEquals(10, meta.get("total"));
        assertTrue(result.hasNext());
        assertEquals(10, result.total());
    }

    @Test
    public void an_uncounted_page_omits_the_total_and_says_why() {
        PaginatedResult<String> result = new PaginatedResult<>(
            List.of("a", "b"), 0, 0, 2, "/x", false);
        Map<String, Object> meta = result.metadata();
        assertFalse(meta.containsKey("total"));
        assertEquals(Boolean.FALSE, meta.get("counted"));
        assertEquals(2, meta.get("count"));
    }

    @Test
    public void an_uncounted_full_page_offers_the_next_one() {
        PaginatedResult<String> result = new PaginatedResult<>(
            List.of("a", "b"), 0, 0, 2, "/x", false);
        assertTrue(result.hasNext());

        Map<String, Object> links = result.links();
        assertTrue("a full page may have more items", links.containsKey("next"));
    }

    @Test
    public void an_uncounted_short_page_ends_the_listing() {
        PaginatedResult<String> result = new PaginatedResult<>(
            List.of("a"), 0, 0, 2, "/x", false);
        assertFalse(result.hasNext());
        assertFalse(result.links().containsKey("next"));
    }

    @Test
    public void pagination_defaults_to_counted() {
        assertTrue(new Pagination(0, 100).counted());
        assertFalse(new Pagination(0, 100, false).counted());
    }

    @Test
    public void pagination_still_clamps() {
        Pagination clamped = new Pagination(-5, 5000);
        assertEquals(0, clamped.offset());
        assertEquals(1000, clamped.limit());
        assertTrue(clamped.counted());
    }
}
