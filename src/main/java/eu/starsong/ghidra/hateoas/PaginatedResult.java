package eu.starsong.ghidra.hateoas;

import com.google.gson.Gson;
import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Represents a paginated collection of items with HATEOAS metadata.
 *
 * @param <T> The type of items in the result
 */
public class PaginatedResult<T> {

    private final List<T> items;
    private final int total;
    private final int offset;
    private final int limit;
    private final String basePath;
    private final boolean counted;
    private Function<T, Map<String, Object>> itemLinksBuilder;

    public PaginatedResult(List<T> items, int total, int offset, int limit, String basePath) {
        this(items, total, offset, limit, basePath, true);
    }

    /**
     * @param counted when false the total was never computed: the metadata
     *                omits {@code total}, says {@code counted: false}, and the
     *                next link is emitted from the page being full rather than
     *                from a total that does not exist.
     */
    public PaginatedResult(List<T> items, int total, int offset, int limit,
                           String basePath, boolean counted) {
        this.items = items;
        this.total = total;
        this.offset = offset;
        this.limit = limit;
        this.basePath = basePath;
        this.counted = counted;
    }

    /**
     * Get the paginated items.
     */
    public List<T> items() {
        return items;
    }

    /**
     * Get the total count of items (before pagination).
     */
    public int total() {
        return total;
    }

    /**
     * Get the offset used.
     */
    public int offset() {
        return offset;
    }

    /**
     * Get the limit used.
     */
    public int limit() {
        return limit;
    }

    /**
     * Check if there is a next page.
     */
    public boolean hasNext() {
        if (!counted) {
            // Without a total the only honest signal is a full page.
            return items.size() >= limit;
        }
        return offset + items.size() < total;
    }

    /**
     * Check if there is a previous page.
     */
    public boolean hasPrev() {
        return offset > 0;
    }

    /**
     * Set a function to build links for each item.
     */
    public PaginatedResult<T> withItemLinks(Function<T, Map<String, Object>> linksBuilder) {
        this.itemLinksBuilder = linksBuilder;
        return this;
    }

    /**
     * Build a Response with pagination metadata and links.
     */
    public Response toResponse() {
        return toResponse(null, 0);
    }

    /**
     * Build a Response with pagination metadata and links, including the
     * top-level id/instance/timestamp meta fields for HATEOAS compliance.
     */
    public Response toResponse(Context ctx, int port) {
        List<?> resultItems = itemLinksBuilder != null
            ? items.stream().map(this::wrapWithLinks).toList()
            : items;

        Response r = ctx != null
            ? Response.ok(ctx, port, resultItems)
            : Response.ok(resultItems);
        if (counted) {
            return r.pagination(offset, limit, total, items.size(), basePath);
        }
        // Uncounted: no total, and the client is told why it is missing.
        r.meta("offset", offset).meta("limit", limit).meta("counted", false);
        r.link("self", basePath + "?offset=" + offset + "&limit=" + limit);
        if (items.size() >= limit) {
            r.link("next", basePath + "?offset=" + (offset + limit) + "&limit=" + limit);
        }
        if (offset > 0) {
            r.link("prev", basePath + "?offset=" + Math.max(0, offset - limit)
                + "&limit=" + limit);
        }
        return r;
    }

    /**
     * Build metadata map for embedding in custom responses.
     */
    public Map<String, Object> metadata() {
        Map<String, Object> meta = new LinkedHashMap<>();
        if (counted) {
            meta.put("total", total);
        } else {
            // No total was computed; saying so is better than a number the
            // caller would take for the count of matches.
            meta.put("counted", false);
        }
        meta.put("offset", offset);
        meta.put("limit", limit);
        meta.put("count", items.size());
        return meta;
    }

    /**
     * Build pagination links map.
     *
     * <p>Delegates to {@link #toResponse()} so the self/next/prev rels, the
     * hrefs and the counted/uncounted "next" rule have a single
     * implementation, then returns just the links.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> links() {
        Map<String, Object> built = toResponse().build();
        Object links = built.get("_links");
        return links instanceof Map
            ? (Map<String, Object>) links
            : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    private Object wrapWithLinks(T item) {
        if (itemLinksBuilder == null) {
            return item;
        }

        Map<String, Object> itemLinks = itemLinksBuilder.apply(item);
        if (itemLinks == null || itemLinks.isEmpty()) {
            return item;
        }

        if (item instanceof Map) {
            Map<String, Object> result = new LinkedHashMap<>((Map<String, Object>) item);
            result.put("_links", itemLinks);
            return result;
        }

        // Flatten: convert the record to a JSON object and embed _links
        // directly at the top level so the JSON shape is
        //   {"name": ..., "address": ..., "_links": {...}}
        // rather than {"data": {...}, "_links": {...}}. This matches main's
        // shape and what the bridge/CLI/tests expect.
        //
        // toJsonTree() instead of toJson()+fromJson(): the round trip
        // serialised and re-parsed every item only to copy the fields into a
        // Map, which allocated a second copy of the whole page.
        try {
            com.google.gson.JsonElement tree = GSON.toJsonTree(item);
            if (!tree.isJsonObject()) {
                return item;
            }
            com.google.gson.JsonObject object = tree.getAsJsonObject();
            object.add("_links", GSON.toJsonTree(itemLinks));
            return object;
        } catch (Exception e) {
            // Fallback: if the item doesn't serialize to a JSON object,
            // leave it alone rather than fabricate a wrapper.
            return item;
        }
    }

    // serializeNulls and disableHtmlEscaping mirror the server's GsonMapper,
    // so an item rendered here matches one rendered by the response mapper.
    // LONG_OR_DOUBLE: without it, the fromJson(..., Map.class) round trip
    // turned every integral field into a Double ("size": 1024.0 in the output).
    private static final Gson GSON = new com.google.gson.GsonBuilder()
        .serializeNulls()
        .disableHtmlEscaping()
        .setObjectToNumberStrategy(com.google.gson.ToNumberPolicy.LONG_OR_DOUBLE)
        .create();
}
