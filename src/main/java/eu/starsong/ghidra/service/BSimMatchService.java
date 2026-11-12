package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.lang.ref.WeakReference;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Per-server, bounded selections. A selected row is never replaced by a new best match. */
public final class BSimMatchService {
    private static final int CAPACITY = 256;
    private final Map<String, Selection> selections = new LinkedHashMap<>();

    record Selection(WeakReference<Program> program, long modification,
            String address, String profile, Map<String, Object> match) {}

    public void register(Program program, Map<String, Object> query) {
        if (!Boolean.TRUE.equals(query.get("success"))) return;
        if (!(query.get("matches") instanceof List<?> rows) || rows.isEmpty()) return;
        registerRows(program, query, List.of(query), false);
    }

    /** Register one bounded response atomically, preserving every row's qualified source. */
    public void registerMulti(Program program, Map<String, Object> query) {
        if (!(query.get("results") instanceof List<?> raw)) throw stale();
        List<Map<String, Object>> sources = new java.util.ArrayList<>();
        for (Object value : raw) {
            if (!(value instanceof Map<?, ?> source)) throw stale();
            @SuppressWarnings("unchecked")
            Map<String, Object> typed = (Map<String, Object>) source;
            sources.add(typed);
        }
        registerRows(program, query, sources, true);
    }

    private void registerRows(Program program, Map<String, Object> query,
            List<Map<String, Object>> sources, boolean bounded) {
        // Profile context is request-thread-local, not available on the EDT.
        String profile = profile();
        if (!(query.get("source_modification") instanceof Number modification)) {
            if (!bounded && !query.containsKey("matches")) return;
            throw stale();
        }
        GhidraSwing.runRead(() -> {
            if (program == null || program.isClosed()
                    || program.getModificationNumber() != modification.longValue()) throw stale();
            Map<String, Selection> pending = new LinkedHashMap<>();
            Map<Map<String, Object>, String> ids = new java.util.IdentityHashMap<>();
            for (Map<String, Object> source : sources) {
                if (!(source.get("matches") instanceof List<?> rows) || rows.isEmpty()) continue;
                if (!Boolean.TRUE.equals(source.get("success"))
                        || !(source.get("source_address") instanceof String address)
                        || !(source.get("source_modification") instanceof Number stamp)
                        || stamp.longValue() != modification.longValue()) throw stale();
                for (Object row : rows) {
                    if (!(row instanceof Map<?, ?> raw)) throw stale();
                    Map<String, Object> match = new LinkedHashMap<>();
                    raw.forEach((key, value) -> match.put(String.valueOf(key), value));
                    String id = UUID.randomUUID().toString();
                    match.put("match_id", id);
                    pending.put(id, new Selection(new WeakReference<>(program),
                        modification.longValue(), address, profile, Collections.unmodifiableMap(match)));
                    @SuppressWarnings("unchecked")
                    Map<String, Object> responseRow = (Map<String, Object>) raw;
                    ids.put(responseRow, id);
                }
            }
            if (bounded && pending.size() > BSimMultiQueryService.MAX_CANDIDATES) throw new ConnectionException(
                "BSIM_BATCH_INVALID", 400, "One response cannot register more than 200 candidates");
            synchronized (selections) {
                selections.putAll(pending);
                ids.forEach((row, id) -> row.put("match_id", id));
                while (selections.size() > CAPACITY) selections.remove(selections.keySet().iterator().next());
            }
            return null;
        });
    }

    public Map<String, Object> inspect(Program program, String id, int maxCodeLines) {
        Selection selected = require(program, id);
        Function function = GhidraSwing.runRead(() -> {
            check(program, selected);
            Function found = program.getFunctionManager().getFunctionAt(
                GhidraUtil.resolveAddress(program, selected.address(), false));
            if (found == null) throw stale();
            return found;
        });
        Map<String, Object> snapshot = BSimFunctionSnapshot.capture(program, function, maxCodeLines);
        GhidraSwing.runRead(() -> { check(program, selected); return null; });
        Map<String, Object> target = new LinkedHashMap<>();
        target.put("md5", ((Map<?, ?>) snapshot.get("program")).get("md5"));
        target.put("address", selected.address());
        target.put("modification", selected.modification());
        Map<String, Object> selection = new LinkedHashMap<>();
        selection.put("match_id", id);
        selection.put("profile", selected.profile());
        selection.put("target", target);
        selection.put("match", selected.match());
        return Map.of("selection", selection, "target", snapshot);
    }

    public Map<String, Object> selection(Program program, String id) {
        Selection selected = require(program, id);
        return GhidraSwing.runRead(() -> {
            check(program, selected);
            Map<String, Object> target = new LinkedHashMap<>();
            target.put("md5", program.getExecutableMD5());
            target.put("address", selected.address());
            target.put("modification", selected.modification());
            return Map.of("selection", Map.of("match_id", id, "profile", selected.profile(),
                "target", target, "match", selected.match()));
        });
    }

    public Map<String, Object> validate(Program program, String id) {
        require(program, id);
        return Map.of("valid", true, "match_id", id);
    }

    Selection require(Program program, String id) {
        Selection selected;
        synchronized (selections) { selected = selections.get(id); }
        if (selected == null) throw new ConnectionException("BSIM_MATCH_UNKNOWN", 404,
            "The selected match is unknown or was evicted. Query again and select a returned match ID.");
        if (!selected.profile().equals(profile())) throw new ConnectionException(
            "BSIM_MATCH_PROFILE", 409, "Use the BSim profile that produced this match.");
        GhidraSwing.runRead(() -> { check(program, selected); return null; });
        return selected;
    }

    static void check(Program program, Selection selected) {
        if (program == null || selected.program().get() != program || program.isClosed()
                || program.getModificationNumber() != selected.modification()) throw stale();
    }

    private static String profile() {
        var selected = ConnectionProfiles.currentBsim();
        return selected == null ? "" : selected.id();
    }

    private static ConnectionException stale() {
        return new ConnectionException("BSIM_MATCH_STALE", 409,
            "The source program changed or is no longer active. Query again before comparing.");
    }

    static String qualifiedAddress(Function function) {
        var address = function.getEntryPoint();
        return address.getAddressSpace().getName() + "::0x" + Long.toHexString(address.getOffset());
    }

    /** Only credential-free native repository links may leave a query worker. */
    static String safeRepositoryUrl(Object value) {
        if (!(value instanceof String text) || text.isBlank()) return null;
        try {
            URI uri = new URI(text);
            if (!"ghidra".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                    || uri.getRawFragment() != null || uri.getPath() == null
                    || !uri.getPath().startsWith("/") || uri.getPath().contains("\\")) return null;
            for (String component : uri.getPath().substring(1).split("/", -1)) {
                if (component.isBlank() || component.equals(".") || component.equals("..")) return null;
                for (int i = 0; i < component.length(); i++) {
                    if (Character.isISOControl(component.charAt(i))) return null;
                }
            }
            return uri.toASCIIString();
        } catch (Exception invalid) { return null; }
    }
}
