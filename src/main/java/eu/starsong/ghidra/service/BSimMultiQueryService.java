package eu.starsong.ghidra.service;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.io.StringReader;
import java.lang.ref.WeakReference;
import java.util.*;

/** Bounded address pages and explicit batches; every candidate remains an explicit selection. */
public final class BSimMultiQueryService {
    public static final int MAX_FUNCTIONS = 100;
    public static final int MAX_MATCHES = 10;
    public static final int MAX_CANDIDATES = 200;
    public static final int MAX_ADDRESSES_TEXT = 16384;
    private record ProgramIdentity(WeakReference<Program> program, String id) {}
    private static final List<ProgramIdentity> PROGRAM_IDENTITIES = new ArrayList<>();

    /** Weak ownership, and reference equality rather than a file/path or Program.equals identity. */
    static synchronized String programId(Program program) {
        PROGRAM_IDENTITIES.removeIf(entry -> {
            Program candidate = entry.program().get();
            return candidate == null || candidate.isClosed();
        });
        for (ProgramIdentity entry : PROGRAM_IDENTITIES)
            if (entry.program().get() == program) return entry.id();
        String id = UUID.randomUUID().toString();
        PROGRAM_IDENTITIES.add(new ProgramIdentity(new WeakReference<>(program), id));
        return id;
    }
    private BSimMultiQueryService() {}

    record Identity(long offset, String name) {}
    record Source(Function function, Identity identity, Address address, Map<String, Object> row) {}
    record Page(long modification, String program, String programId, List<Source> sources, boolean more) {}

    /** Signature seam lets native protocol regressions use synthetic vectors, not a fake query engine. */
    interface Signatures extends AutoCloseable {
        void scan(Function function) throws Exception;
        Object descriptions() throws Exception;
        void close();
    }
    interface SignatureFactory {
        Signatures create(Object connection, Object info, Program program) throws Exception;
    }
    private static final SignatureFactory NATIVE_SIGNATURES = (connection, info, program) -> {
        Object generator = BSimQueryService.newGenerator(connection, info, program);
        return new Signatures() {
            public void scan(Function function) throws Exception {
                generator.getClass().getMethod("scanFunction", Function.class).invoke(generator, function);
            }
            public Object descriptions() throws Exception {
                return generator.getClass().getMethod("getDescriptionManager").invoke(generator);
            }
            public void close() { BSimDatabase.disposeQuietly(generator); }
        };
    };

    public static Map<String, Object> overview(Program program, int offset, int maxFunctions,
            int maxMatches, double similarity, double significance, Long expectedModification, String expectedProgram,
            String executable, String architecture, String compiler, String categories) {
        return run(program, null, offset, maxFunctions, maxMatches, similarity, significance,
            expectedModification, expectedProgram, executable, architecture, compiler, categories, NATIVE_SIGNATURES);
    }

    public static Map<String, Object> batch(Program program, String addresses, int maxMatches,
            double similarity, double significance, Long expectedModification, String expectedProgram, String executable,
            String architecture, String compiler, String categories) {
        return run(program, addresses, 0, 0, maxMatches, similarity, significance,
            expectedModification, expectedProgram, executable, architecture, compiler, categories, NATIVE_SIGNATURES);
    }

    static Map<String, Object> run(Program program, String addresses, int offset, int maxFunctions,
            int maxMatches, double similarity, double significance, Long expectedModification, String expectedProgram,
            String executable, String architecture, String compiler, String categories,
            SignatureFactory factory) {
        boolean overview = addresses == null && maxFunctions != 0;
        Map<String, Object> data = new LinkedHashMap<>();
        List<String> requested;
        BSimMetadataFilter metadata;
        try {
            requested = overview ? null : parseAddresses(addresses);
            int count = overview ? maxFunctions : requested.size();
            if (offset < 0 || count < 1 || count > MAX_FUNCTIONS || maxMatches < 1
                    || maxMatches > MAX_MATCHES || count * maxMatches > MAX_CANDIDATES
                    || !Double.isFinite(similarity) || similarity < 0 || similarity > 1
                    || !Double.isFinite(significance) || significance < 0
                    || (expectedModification != null && expectedModification < 0)) {
                throw new IllegalArgumentException("offset must be nonnegative; source count 1..100, max_matches 1..10, product <=200; similarity 0..1 and significance nonnegative");
            }
            if ((expectedProgram != null && expectedProgram.isBlank())
                    || (overview && offset > 0 && expectedModification != null && expectedProgram == null))
                throw new IllegalArgumentException("stamped overview continuation requires expected_program from source_program_id");
            metadata = BSimMetadataFilter.parse(executable, architecture, compiler, categories);
        } catch (IllegalArgumentException invalid) {
            return BSimDatabase.failure(data, "BSIM_BATCH_INVALID", invalid.getMessage());
        }
        if (program == null) return BSimDatabase.failure(data, "BSIM_NO_PROGRAM", "no program is open");
        Object consumer = new Object();
        boolean pinned = GhidraSwing.runUninterruptibly(() -> program.addConsumer(consumer));
        if (!pinned) return BSimDatabase.failure(data, "BSIM_MATCH_STALE", "the source program is closed");
        try {
            Page page;
            try {
                page = GhidraSwing.runRead(() -> select(program, requested, offset,
                    maxFunctions, expectedModification, expectedProgram));
            } catch (IllegalArgumentException invalid) {
                return BSimDatabase.failure(data, "BSIM_BATCH_INVALID", invalid.getMessage());
            }
            List<Map<String, Object>> rows = GhidraSwing.runRead(() -> {
            data.put("mode", overview ? "overview" : "batch");
            data.put("program", page.program());
            data.put("source_modification", page.modification());
            data.put("source_program_id", page.programId());
            data.put("filters", metadata.predicates());
            data.put("available_categories", List.of());
            data.put("max_matches", maxMatches);
            data.put("min_similarity", similarity);
            data.put("min_significance", significance);
            data.put("scanned", page.sources().size());
            data.put("searched", 0);
            data.put("scope", overview ? "address-ordered page; ranking is within this page only" : "explicit source addresses only");
            if (overview) {
                data.put("offset", offset);
                data.put("max_functions", maxFunctions);
                data.put("has_more", page.more());
                data.put("next_offset", page.more() ? (long) offset + page.sources().size() : null);
            }
            List<Map<String, Object>> resultRows = new ArrayList<>();
            for (Source source : page.sources()) resultRows.add(source.row());
            data.put("results", resultRows);
            return resultRows;
            });
            search(program, page, data, metadata, maxMatches, similarity, significance, factory);
            return GhidraSwing.runRead(() -> {
                checkStamp(program, page.modification());
                if (overview) rank(page.sources(), rows);
                roundScores(rows);
                data.put("complete", !page.more() && rows.stream().allMatch(row -> Boolean.TRUE.equals(row.get("complete"))));
                data.put("success", true);
                return data;
            });
        } finally {
            GhidraSwing.runUninterruptibly(() -> { program.release(consumer); return null; });
        }
    }

    static List<String> parseAddresses(String json) {
        if (json == null || json.length() > MAX_ADDRESSES_TEXT) throw new IllegalArgumentException("addresses must be JSON text of at most 16384 characters");
        List<String> result = new ArrayList<>();
        Set<String> distinct = new HashSet<>();
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            reader.setLenient(false);
            if (reader.peek() != JsonToken.BEGIN_ARRAY) throw new IllegalArgumentException("addresses must be a JSON array");
            reader.beginArray();
            while (reader.hasNext()) {
                if (result.size() >= MAX_FUNCTIONS || reader.peek() != JsonToken.STRING) throw new IllegalArgumentException("addresses requires 1..100 distinct strings");
                String text = reader.nextString();
                if (text.isBlank() || !text.equals(text.trim()) || text.chars().anyMatch(Character::isISOControl)
                        || !distinct.add(text)) throw new IllegalArgumentException("addresses must be unique nonblank exact addresses");
                result.add(text);
            }
            reader.endArray();
            if (result.isEmpty() || reader.peek() != JsonToken.END_DOCUMENT) throw new IllegalArgumentException("addresses requires one nonempty array");
        } catch (java.io.IOException | IllegalStateException malformed) {
            throw new IllegalArgumentException("addresses must be one JSON array of exact address strings", malformed);
        }
        return result;
    }

    private static Page select(Program program, List<String> requested, int offset,
            int limit, Long expected, String expectedProgram) {
        long stamp = program.getModificationNumber();
        String id = programId(program);
        if (expectedProgram != null && !expectedProgram.equals(id))
            throw new ConnectionException("BSIM_MATCH_STALE", 409,
                "source program instance changed; restart with a fresh source_program_id and source_modification");
        checkStamp(program, expected == null ? stamp : expected);
        List<Source> sources = new ArrayList<>();
        boolean more = false;
        if (requested != null) {
            Set<Address> entries = new HashSet<>();
            for (String text : requested) {
                Address address = exactAddress(program, text);
                if (!entries.add(address)) throw new IllegalArgumentException("addresses resolve to the same canonical entry: " + text);
                Function function = program.getFunctionManager().getFunctionAt(address);
                sources.add(source(function, address, stamp));
            }
        } else {
            // Ghidra's ordinary iterator excludes externals. Merge that ordered iterator with
            // the native address-ordered external iterator using constant lookahead.
            var externals = program.getFunctionManager().getExternalFunctions();
            var internal = program.getFunctionManager().getFunctions(true);
            Function next = internal.hasNext() ? internal.next() : null;
            Function external = externals.hasNext() ? externals.next() : null;
            long position = 0;
            while (next != null || external != null) {
                Function function;
                if (next == null || (external != null
                        && external.getEntryPoint().compareTo(next.getEntryPoint()) < 0)) {
                    function = external;
                    external = externals.hasNext() ? externals.next() : null;
                } else {
                    function = next;
                    next = internal.hasNext() ? internal.next() : null;
                    if (function.isExternal()) continue;
                }
                if (position++ < offset) continue;
                if (sources.size() == limit) { more = true; break; }
                sources.add(source(function, function.getEntryPoint(), stamp));
            }
        }
        Map<Identity, List<Source>> identities = new HashMap<>();
        for (Source source : sources) if (source.identity() != null)
            identities.computeIfAbsent(source.identity(), key -> new ArrayList<>()).add(source);
        for (List<Source> collisions : identities.values()) if (collisions.size() > 1)
            for (Source source : collisions) fail(source.row(), "error", "BSIM_SOURCE_AMBIGUOUS",
                "native BSim offset/FQN identity collides across address spaces");
        checkStamp(program, stamp);
        return new Page(stamp, program.getName(), id, sources, more);
    }

    static Address exactAddress(Program program, String text) {
        try {
            int separator = text.indexOf("::");
            Address address;
            if (separator >= 0) {
                String spaceName = text.substring(0, separator);
                String offset = text.substring(separator + 2);
                var space = program.getAddressFactory().getAddressSpace(spaceName);
                if (space == null || !offset.matches("(?i)(?:0x)?[0-9a-f]+")) throw new IllegalArgumentException("invalid qualified address: " + text);
                address = space.getAddress(Long.parseUnsignedLong(
                    offset.startsWith("0x") || offset.startsWith("0X") ? offset.substring(2) : offset, 16));
            } else {
                address = program.getAddressFactory().getAddress(text);
            }
            if (address == null || !program.getAddressFactory().isValidAddress(address)) throw new IllegalArgumentException("invalid address: " + text);
            return address;
        } catch (Exception invalid) {
            throw new IllegalArgumentException("invalid exact function-entry address: " + text, invalid);
        }
    }

    private static Source source(Function function, Address address, long stamp) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("source_address", address.getAddressSpace().getName() + "::0x" + Long.toHexString(address.getOffset()));
        row.put("function", function == null ? null : function.getName(true));
        row.put("source_modification", stamp);
        row.put("matches", new ArrayList<Map<String, Object>>());
        row.put("returned", 0);
        row.put("complete", false);
        row.put("success", false);
        row.put("status", "error");
        if (function == null) fail(row, "error", "BSIM_NO_FUNCTION", "no function at this exact entry address");
        else if (function.isExternal() || function.isThunk() || function.getBody() == null || function.getBody().isEmpty())
            fail(row, "skipped", "BSIM_NO_BODY", "external, thunk or bodyless function has no eligible signature");
        return new Source(function, function == null ? null : new Identity(address.getOffset(), function.getName(true)), address, row);
    }

    private static void search(Program program, Page page, Map<String, Object> data,
            BSimMetadataFilter metadata, int limit, double similarity, double significance,
            SignatureFactory factory) {
        List<Source> eligible = page.sources().stream().filter(source -> !source.row().containsKey("reason")).toList();
        String database = BSimService.database();
        Map<String, Object> failure = new LinkedHashMap<>();
        if (!BSimService.available()) BSimDatabase.failure(failure, "BSIM_DISABLED", "this Ghidra build has no BSim engine");
        else if (database == null) BSimDatabase.failure(failure, "BSIM_NO_DATABASE", "no signature database is configured");
        Object connection = failure.isEmpty() ? BSimDatabase.open(database, false, failure) : null;
        if (connection == null) {
            failSources(eligible, String.valueOf(failure.get("code")), String.valueOf(failure.get("reason")));
            return;
        }
        try {
            Object info = connection.getClass().getMethod("getInfo").invoke(connection);
            List<String> categories = BSimMetadataFilter.availableCategories(info);
            GhidraSwing.runRead(() -> { data.put("available_categories", categories); return null; });
            Object nativeFilter;
            try {
                nativeFilter = metadata.build(connection, info);
            } catch (IllegalArgumentException invalid) {
                failSources(eligible, "BSIM_FILTER_INVALID", invalid.getMessage()); return;
            } catch (Throwable unsupported) {
                failSources(eligible, "BSIM_FILTER_UNSUPPORTED", BSimDatabase.describe(BSimDatabase.unwrap(unsupported))); return;
            }
            if (eligible.isEmpty()) return;
            try (Signatures signatures = factory.create(connection, info, program)) {
                for (Source source : eligible) {
                    GhidraSwing.runRead(() -> { checkStamp(program, page.modification()); return null; });
                    try { signatures.scan(source.function()); }
                    catch (Exception failed) {
                        GhidraSwing.runRead(() -> { fail(source.row(), "error", "BSIM_SCAN_FAILED", BSimDatabase.describe(BSimDatabase.unwrap(failed))); return null; });
                    }
                }
                Object descriptions = selectedDescriptions(signatures.descriptions(), eligible,
                    connection.getClass().getMethod("getLSHVectorFactory").invoke(connection), significance);
                List<Source> searched = eligible.stream().filter(source -> !source.row().containsKey("reason")).toList();
                GhidraSwing.runRead(() -> { checkStamp(program, page.modification()); data.put("searched", searched.size()); return null; });
                if (searched.isEmpty()) return;
                Object response = BSimQueryService.executeNearest(connection, descriptions, limit,
                    similarity, significance, nativeFilter, null);
                if (response == null) throw new IllegalStateException("native QueryNearest failed: " + BSimDatabase.lastError(connection));
                GhidraSwing.runRead(() -> {
                    checkStamp(program, page.modification());
                    correlate(response, searched, limit);
                    return null;
                });
            }
        } catch (ConnectionException stale) { throw stale; }
        catch (Throwable failed) {
            failSources(eligible, "BSIM_QUERY_FAILED", BSimDatabase.describe(BSimDatabase.unwrap(failed)));
        } finally { BSimDatabase.release(connection, database); }
    }

    /** Exclude callgraph-only, failed and unrequested descriptions before the one native query. */
    private static Object selectedDescriptions(Object generated, List<Source> sources,
            Object vectorFactory, double minSignificance) throws Exception {
        if (generated == null) throw new IllegalStateException("signature generator returned no descriptions");
        Class<?> managerClass = generated.getClass();
        Object selected = managerClass.getConstructor().newInstance();
        managerClass.getMethod("transferSettings", managerClass).invoke(selected, generated);
        Map<Identity, Object> descriptions = new HashMap<>();
        Set<Identity> ambiguous = new HashSet<>();
        Iterator<?> iterator = (Iterator<?>) managerClass.getMethod("listAllFunctions").invoke(generated);
        while (iterator.hasNext()) {
            Object description = iterator.next();
            if (BSimDatabase.call(description, "getSignatureRecord") == null) continue;
            Identity identity = identity(description);
            if (descriptions.putIfAbsent(identity, description) != null) ambiguous.add(identity);
        }
        Class<?> descriptionClass = Class.forName("ghidra.features.bsim.query.description.FunctionDescription", true, BSimDatabase.loader());
        Class<?> executableClass = Class.forName("ghidra.features.bsim.query.description.ExecutableRecord", true, BSimDatabase.loader());
        Class<?> signatureClass = Class.forName("ghidra.features.bsim.query.description.SignatureRecord", true, BSimDatabase.loader());
        for (Source source : sources) {
            if (source.row().containsKey("reason")) continue;
            if (ambiguous.contains(source.identity())) {
                GhidraSwing.runRead(() -> { fail(source.row(), "error", "BSIM_SOURCE_AMBIGUOUS",
                    "multiple signed native descriptions share this source offset/FQN"); return null; });
                continue;
            }
            Object description = descriptions.get(source.identity());
            Object signature = description == null ? null : BSimDatabase.call(description, "getSignatureRecord");
            if (signature == null) {
                GhidraSwing.runRead(() -> { fail(source.row(), "error", "BSIM_SCAN_FAILED", "no signature generated for this source; corpus was not searched"); return null; });
                continue;
            }
            Object vector = BSimDatabase.call(signature, "getLSHVector");
            double selfSignificance = ((Number) vectorFactory.getClass().getMethod("getSelfSignificance",
                Class.forName("generic.lsh.vector.LSHVector", true, BSimDatabase.loader()))
                .invoke(vectorFactory, vector)).doubleValue();
            if (!Double.isFinite(selfSignificance) || selfSignificance < minSignificance) {
                GhidraSwing.runRead(() -> { fail(source.row(), "skipped", "BSIM_BELOW_THRESHOLD",
                    "source signature self-significance is below min_significance; native BSim would not search it"); return null; });
                continue;
            }
            Object executable = managerClass.getMethod("transferExecutable", executableClass)
                .invoke(selected, BSimDatabase.call(description, "getExecutableRecord"));
            Object copied = managerClass.getMethod("newFunctionDescription", String.class, long.class, executableClass)
                .invoke(selected, source.identity().name(), source.identity().offset(), executable);
            managerClass.getMethod("attachSignature", descriptionClass, signatureClass).invoke(selected, copied, signature);
        }
        return selected;
    }

    private static Identity identity(Object description) {
        Object name = BSimDatabase.call(description, "getFunctionName");
        Object offset = BSimDatabase.call(description, "getAddress");
        if (!(name instanceof String text) || !(offset instanceof Number number)) throw new IllegalStateException("native BSim returned an invalid source identity");
        return new Identity(number.longValue(), text);
    }

    static void correlate(Object response, List<Source> sources, int limit) throws Exception {
        Object count = response.getClass().getField("totalfunc").get(response);
        if (!(count instanceof Number number) || number.intValue() != sources.size())
            throw new IllegalStateException("native BSim did not search every signed source");
        Object groups = response.getClass().getField("result").get(response);
        if (!(groups instanceof Iterable<?> iterable)) throw new IllegalStateException("native BSim returned no result groups");
        Map<Identity, Source> byIdentity = new HashMap<>();
        for (Source source : sources) byIdentity.put(source.identity(), source);
        Set<Identity> seen = new HashSet<>();
        for (Object group : iterable) {
            Object base = group.getClass().getMethod("getBase").invoke(group);
            Identity identity = identity(base);
            Source source = byIdentity.get(identity);
            if (source == null || !seen.add(identity)) throw new IllegalStateException("native BSim returned an unknown or duplicate source group");
            List<Map<String, Object>> matches = new ArrayList<>();
            for (Object note : (Iterable<?>) group) {
                matches.add(BSimQueryService.describeNote(note, false));
            }
            matches.sort(Comparator.<Map<String, Object>>comparingDouble(row -> ((Number) row.get("similarity")).doubleValue()).reversed()
                .thenComparing(Comparator.comparingDouble((Map<String, Object> row) -> ((Number) row.get("significance")).doubleValue()).reversed()));
            if (matches.size() > limit) matches.subList(limit, matches.size()).clear();
            source.row().put("matches", matches);
            source.row().put("returned", matches.size());
            source.row().put("success", true);
            source.row().put("status", matches.isEmpty() ? "no_match" : "matched");
            // Native total counts can include candidates rejected by metadata/significance.
            // Do not interpret that number as an exact post-filter total.
            Object total = BSimDatabase.call(group, "getTotalCount");
            boolean complete = matches.size() < limit && total instanceof Number countTotal
                && countTotal.longValue() < 2_000_000;
            source.row().put("complete", complete);
            if (!complete) source.row().put("reason", "native candidate search or response limit reached; additional qualifying matches may exist");
            else if (matches.isEmpty()) source.row().put("reason", "no qualifying candidate returned for this source at the requested thresholds and filters");
        }
        // H2 counts submitted functions even when a parallel vector task fails; absent groups
        // therefore prove neither successful execution nor a scoped no-match.
        for (Source source : sources) if (!seen.contains(source.identity())) {
            fail(source.row(), "error", "BSIM_QUERY_UNVERIFIED",
                "native result omitted this source; vector-query completion and absence of qualifying matches cannot be verified");
        }
    }

    static void rank(List<Source> sources, List<Map<String, Object>> rows) {
        Map<String, Address> addresses = new HashMap<>();
        for (Source source : sources) addresses.put((String) source.row().get("source_address"), source.address());
        rows.sort(Comparator.<Map<String, Object>>comparingDouble(row -> best(row, "similarity")).reversed()
            .thenComparing(Comparator.comparingDouble((Map<String, Object> row) -> best(row, "significance")).reversed())
            .thenComparing(row -> addresses.get(row.get("source_address"))));
    }
    private static double best(Map<String, Object> row, String score) {
        List<?> matches = (List<?>) row.get("matches");
        return matches.isEmpty() ? -Double.MAX_VALUE : ((Number) ((Map<?, ?>) matches.get(0)).get(score)).doubleValue();
    }
    static void roundScores(List<Map<String, Object>> rows) {
        for (Map<String, Object> row : rows) for (Object value : (List<?>) row.get("matches")) {
            @SuppressWarnings("unchecked") Map<String, Object> match = (Map<String, Object>) value;
            for (String score : List.of("similarity", "significance"))
                match.put(score, Math.round(((Number) match.get(score)).doubleValue() * 1000.0) / 1000.0);
        }
    }
    private static void failSources(List<Source> sources, String code, String reason) {
        GhidraSwing.runRead(() -> {
            for (Source source : sources) if (!source.row().containsKey("reason") || Boolean.TRUE.equals(source.row().get("success")))
                fail(source.row(), "error", code, reason);
            return null;
        });
    }
    private static void fail(Map<String, Object> row, String status, String code, String reason) {
        row.put("success", false); row.put("status", status); row.put("code", code); row.put("reason", reason);
        row.put("matches", new ArrayList<>()); row.put("returned", 0); row.put("complete", false);
    }
    static void checkStamp(Program program, long modification) {
        if (program.isClosed() || program.getModificationNumber() != modification)
            throw new ConnectionException("BSIM_MATCH_STALE", 409, "source program changed; restart the overview or batch with a fresh source_modification");
    }
}
