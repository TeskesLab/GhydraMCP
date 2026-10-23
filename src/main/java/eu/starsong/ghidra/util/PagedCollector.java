package eu.starsong.ghidra.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Collects one page of a listing without materialising the whole listing.
 *
 * <p>Listing endpoints used to build a DTO for every entity in the program and
 * paginate afterwards, so a 100-item page on a large binary allocated hundreds
 * of thousands of DTOs — on the EDT, which is what freezes the Ghidra UI. The
 * mapper is applied only to the elements that land on the page; the rest are
 * counted but never converted.
 */
public final class PagedCollector {

    private PagedCollector() {
    }

    /**
     * One page of results plus the total number of matching elements.
     *
     * @param items the elements on this page
     * @param total the number of matching elements in the whole source
     */
    public record Page<T>(List<T> items, int total) {
    }

    /**
     * Collect a page out of an iterator.
     *
     * @param source  the elements to page over; must be finite
     * @param include which elements count towards the total (the filter)
     * @param offset  index of the first element on the page
     * @param limit   maximum number of elements on the page
     * @param mapper  converts an element into its response DTO
     */
    public static <S, T> Page<T> collect(Iterator<S> source, Predicate<S> include,
                                         int offset, int limit, Function<S, T> mapper) {
        List<T> items = new ArrayList<>();
        int start = Math.max(0, offset);
        int end = limit < 0 ? Integer.MAX_VALUE : (long) start + limit > Integer.MAX_VALUE
                ? Integer.MAX_VALUE
                : start + limit;
        int matched = 0;

        while (source.hasNext()) {
            S element = source.next();
            if (!include.test(element)) {
                continue;
            }
            if (matched >= start && matched < end) {
                items.add(mapper.apply(element));
            }
            matched++;
        }

        return new Page<>(items, matched);
    }
}
