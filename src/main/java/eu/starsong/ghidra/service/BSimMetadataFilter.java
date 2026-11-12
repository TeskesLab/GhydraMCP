package eu.starsong.ghidra.service;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Exact, conjunctive user filters. Unlike the diff convenience filter, these never fall back. */
public final class BSimMetadataFilter {
    private static final String TYPES = "ghidra.features.bsim.gui.filters.";
    private static final String FILTER = "ghidra.features.bsim.query.protocol.BSimFilter";
    private static final int MAX_VALUE = 4096;
    private static final int MAX_CATEGORIES = 32;
    private static final int MAX_CATEGORY_JSON = 16384;
    private final Map<String, String> metadata;
    private final Map<String, String> categories;

    private BSimMetadataFilter(Map<String, String> metadata, Map<String, String> categories) {
        this.metadata = Collections.unmodifiableMap(metadata);
        this.categories = Collections.unmodifiableMap(categories);
    }

    /**
     * Parse optional exact executable, architecture and compiler values and a JSON category object.
     * Null means absent; supplied values must be nonblank, bounded strings without control characters
     * or surrounding whitespace. Each category name has exactly one value (no implicit OR).
     */
    public static BSimMetadataFilter parse(String executable, String architecture,
            String compiler, String categoryJson) {
        Map<String, String> metadata = new LinkedHashMap<>();
        if (executable != null) metadata.put("executable", value("executable", executable, MAX_VALUE));
        if (architecture != null) metadata.put("architecture", value("architecture", architecture, MAX_VALUE));
        if (compiler != null) metadata.put("compiler", value("compiler", compiler, MAX_VALUE));
        Map<String, String> categories = new LinkedHashMap<>();
        if (categoryJson != null) {
            if (categoryJson.length() > MAX_CATEGORY_JSON) {
                throw new IllegalArgumentException("categories exceeds 16384 characters");
            }
            try (JsonReader reader = new JsonReader(new StringReader(categoryJson))) {
                reader.setLenient(false);
                if (reader.peek() != JsonToken.BEGIN_OBJECT) throw invalidCategories();
                reader.beginObject();
                while (reader.hasNext()) {
                    if (categories.size() >= MAX_CATEGORIES) throw invalidCategories();
                    String name = value("category name", reader.nextName(), 256);
                    if (categories.containsKey(name) || reader.peek() != JsonToken.STRING) {
                        throw invalidCategories();
                    }
                    categories.put(name, value("category value", reader.nextString(), MAX_VALUE));
                }
                reader.endObject();
                if (reader.peek() != JsonToken.END_DOCUMENT) throw invalidCategories();
            } catch (IOException | IllegalStateException malformed) {
                throw invalidCategories();
            }
        }
        return new BSimMetadataFilter(metadata, categories);
    }

    private static IllegalArgumentException invalidCategories() {
        return new IllegalArgumentException("categories must be one JSON object with at most 32 distinct "
            + "nonblank category names and one nonblank string value each");
    }

    private static String value(String name, String text, int max) {
        if (text.isBlank() || text.length() > max || !text.equals(text.trim())
                || text.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + " must be a nonblank string of at most "
                + max + " characters, without surrounding whitespace or control characters");
        }
        return text;
    }

    /** The database's configured category names, not guessed values or client-side labels. */
    static List<String> availableCategories(Object databaseInfo) throws ReflectiveOperationException {
        Object configured = databaseInfo.getClass().getField("execats").get(databaseInfo);
        if (configured == null) return List.of();
        if (!(configured instanceof List<?> names)) {
            throw new IllegalArgumentException("the database has an invalid category configuration");
        }
        List<String> result = new ArrayList<>(names.size());
        for (Object name : names) {
            if (!(name instanceof String text)) {
                throw new IllegalArgumentException("the database has an invalid category configuration");
            }
            result.add(text);
        }
        return result;
    }

    boolean isEmpty() {
        return metadata.isEmpty() && categories.isEmpty();
    }

    /** Build real native filter atoms before executing QueryNearest; every specified atom must survive. */
    Object build(Object connection, Object databaseInfo) throws ReflectiveOperationException {
        if (isEmpty()) return null;
        ClassLoader loader = BSimDatabase.loader();
        // These native backends share AbstractSQLFunctionDatabase's QueryNearest SQL filter path.
        // Unknown implementations must not claim that they honored user predicates.
        if (!Class.forName("ghidra.features.bsim.query.file.H2FileFunctionDatabase", true, loader)
                    .isInstance(connection)
                && !Class.forName("ghidra.features.bsim.query.client.PostgresFunctionDatabase", true, loader)
                    .isInstance(connection)) {
            throw new UnsupportedOperationException("metadata filters require native H2 or PostgreSQL BSim");
        }
        List<String> configured = availableCategories(databaseInfo);
        for (String category : categories.keySet()) {
            if (!configured.contains(category)) {
                throw new IllegalArgumentException("unknown executable category: " + category);
            }
        }
        Class<?> filterClass = Class.forName(FILTER, true, loader);
        Class<?> typeClass = Class.forName(TYPES + "BSimFilterType", true, loader);
        Object filter = filterClass.getConstructor().newInstance();
        Method add = filterClass.getMethod("addAtom", typeClass, String.class);
        String executable = metadata.get("executable");
        if (executable != null) {
            Object type = Class.forName(TYPES + "ExecutableNameBSimFilterType", true, loader)
                .getConstructor().newInstance();
            addExact(filter, type, executable, add, filterClass);
            quoteExecutableSQL(filter, filterClass, executable, loader);
        }
        for (Map.Entry<String, String> entry : metadata.entrySet()) {
            if (entry.getKey().equals("executable")) continue;
            String simpleName = switch (entry.getKey()) {
                case "architecture" -> "ArchitectureBSimFilterType";
                case "compiler" -> "CompilerBSimFilterType";
                default -> throw new IllegalArgumentException("unknown metadata filter");
            };
            Object type = Class.forName(TYPES + simpleName, true, loader).getConstructor().newInstance();
            addExact(filter, type, entry.getValue(), add, filterClass);
        }
        // Native SQL groups by BSimFilterType.compareTo (its label). Each category subtype has
        // its own label, so distinct category names generate separate EXISTS clauses joined AND.
        Class<?> categoryType = Class.forName(TYPES + "ExecutableCategoryBSimFilterType", true, loader);
        for (Map.Entry<String, String> entry : categories.entrySet()) {
            Object type = categoryType.getConstructor(String.class).newInstance(entry.getKey());
            addExact(filter, type, entry.getValue(), add, filterClass);
        }
        return filter;
    }

    /**
     * Ghidra 11 emits executable names as raw SQL literals; 12 escapes them itself. Probe the
     * native SQL emitter, not the version, so neither missing nor double escaping is possible.
     * This filter is used only by native H2/PostgreSQL QueryNearest, never client evaluation.
     * Keep the public predicates unchanged and verify the encoded atom's final SQL before use.
     */
    private static void quoteExecutableSQL(Object filter, Class<?> filterClass, String value,
            ClassLoader loader) throws ReflectiveOperationException {
        String quoted = value.replace("'", "''");
        String prefix = " AND (desctable.id_exe = exetable.id) AND (exetable.name_exec = '";
        String expected = prefix + quoted + "')";
        Class<?> resolution = Class.forName(
            "ghidra.features.bsim.query.client.IDSQLResolution", true, loader);
        Object resolutions = Array.newInstance(resolution, 1);
        Method emit = Class.forName("ghidra.features.bsim.query.client.SQLEffects", true, loader)
            .getMethod("createFilter", filterClass, resolutions.getClass(),
                Class.forName("ghidra.features.bsim.query.SQLFunctionDatabase", true, loader));
        Object clause = emit.invoke(null, filter, resolutions, null);
        Method where = clause.getClass().getMethod("whereClause");
        if (!",exetable".equals(clause.getClass().getMethod("tableClause").invoke(clause))) {
            throw new UnsupportedOperationException("native BSim changed executable SQL filter tables");
        }
        String actual = (String) where.invoke(clause);
        if (expected.equals(actual)) return;
        if ((prefix + value + "')").equals(actual)) {
            // Only the legacy raw-literal emitter gets an SQL-encoded atom value.
            Object atom = filterClass.getMethod("getAtom", int.class).invoke(filter, 0);
            atom.getClass().getField("value").set(atom, quoted);
            clause = emit.invoke(null, filter, resolutions, null);
            if (expected.equals(where.invoke(clause))) return;
        }
        throw new UnsupportedOperationException("native BSim cannot emit an exact executable SQL filter");
    }

    private static void addExact(Object filter, Object type, String value, Method add,
            Class<?> filterClass) throws ReflectiveOperationException {
        int before = ((Number) filterClass.getMethod("numAtoms").invoke(filter)).intValue();
        add.invoke(filter, type, value);
        int after = ((Number) filterClass.getMethod("numAtoms").invoke(filter)).intValue();
        if (after != before + 1) throw new UnsupportedOperationException("native BSim refused a filter atom");
        Object atom = filterClass.getMethod("getAtom", int.class).invoke(filter, before);
        if (!value.equals(atom.getClass().getField("value").get(atom))) {
            throw new UnsupportedOperationException("native BSim changed an exact filter value");
        }
    }

    Map<String, Object> predicates() {
        Map<String, Object> result = new LinkedHashMap<>(metadata);
        if (!categories.isEmpty()) result.put("categories", categories);
        return result;
    }
}
