package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

/** Native GDT transport. Comparison snapshots are deliberately never used as type input. */
public final class BSimSignatureTransfer {
    public static final int MAX_ARCHIVE_BYTES = 524288;
    public static final int MAX_JSON_BYTES = 900000;
    private static final com.google.gson.Gson JSON = new com.google.gson.Gson();
    private static final int MAX_TYPES = 4096;
    private static final java.lang.reflect.Method COMPONENT_COMMENT = componentCommentMethod();

    private static java.lang.reflect.Method componentCommentMethod() {
        try {
            // Like setFieldName, setComment changed its JVM return descriptor.
            return DataTypeComponent.class.getMethod("setComment", String.class);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("Native datatype component comment setter is unavailable", e);
        }
    }
    private BSimSignatureTransfer() {}

    public static Map<String, Object> abi(Program program) {
        return Map.of("language", program.getLanguageID().toString(),
            "compiler", program.getCompilerSpec().getCompilerSpecID().toString(),
            "pointer_size", program.getDefaultPointerSize());
    }

    static Map<String, Object> export(Program program, Function function) {
        Path directory = null;
        FileDataTypeManager archive = null;
        try {
            directory = Files.createTempDirectory("ghydra-signature-");
            Path file = directory.resolve("signature.gdt");
            var ids = GhidraSwing.runRead(() -> program.getLanguage().getLanguageID());
            var compiler = GhidraSwing.runRead(() -> program.getCompilerSpec().getCompilerSpecID());
            archive = FileDataTypeManager.createFileArchive(file.toFile(), ids, compiler);
            FileDataTypeManager destination = archive;
            Map<String, Object> captured = GhidraSwing.runRead(() -> {
                int tx = destination.startTransaction("Export selected function dependencies");
                try {
                    FunctionDefinitionDataType definition = new FunctionDefinitionDataType(function, true);
                    definition.setNameAndCategory(new CategoryPath("/__ghydra_signature_" + UUID.randomUUID()), "selected");
                    definition.setComment(null);
                    for (ParameterDefinition argument : definition.getArguments()) argument.setComment(null);
                    Set<DataType> sourceTypes = Collections.newSetFromMap(new IdentityHashMap<>());
                    visit(definition, sourceTypes);
                    FunctionDefinition exported = (FunctionDefinition) destination.resolve(definition, DataTypeConflictHandler.DEFAULT_HANDLER);
                    List<String> extraRoots = new ArrayList<>();
                    for (var parameter : function.getParameters()) {
                        if (!parameter.isAutoParameter()) continue;
                        visit(parameter.getDataType(), sourceTypes);
                        extraRoots.add(destination.resolve(parameter.getDataType(), DataTypeConflictHandler.DEFAULT_HANDLER).getPathName());
                    }
                    for (DataType source : sourceTypes) {
                        if (source == definition) continue;
                        DataType copied = destination.getDataType(source.getPathName());
                        if (copied == null || !describe(source).equals(describe(copied))) {
                            throw invalid("Native archive changed a source dependency layout: " + source.getPathName());
                        }
                    }
                    // Architecture setup creates an unused default undefined pointer.
                    // Export only the complete selected signature dependency closure.
                    Set<DataType> retained = Collections.newSetFromMap(new IdentityHashMap<>());
                    visit(exported, retained);
                    for (String path : extraRoots) visit(destination.getDataType(path), retained);
                    List<DataType> unused = new ArrayList<>();
                    destination.getAllDataTypes().forEachRemaining(type -> {
                        if (!(type instanceof BuiltInDataType) && !retained.contains(type)) unused.add(type);
                    });
                    for (DataType type : unused) eu.starsong.ghidra.util.GhidraUtil.removeDataType(destination, type);
                    destination.getAllDataTypes().forEachRemaining(BSimSignatureTransfer::clearComments);
                    return Map.<String, Object>of("abi", abi(program), "function", annotation(function),
                        "root", exported.getPathName(), "dependency_roots", List.copyOf(extraRoots));
                } finally { destination.endTransaction(tx, true); }
            });
            archive.save();
            if (Files.size(file) > MAX_ARCHIVE_BYTES) throw oversized();
            byte[] bytes = Files.readAllBytes(file);
            return Map.of("abi", captured.get("abi"), "function", captured.get("function"), "archive", Map.of(
                "format", "ghidra-gdt-v1", "root_type", captured.get("root"),
                "dependency_roots", captured.get("dependency_roots"), "size", bytes.length,
                "sha256", digest(bytes), "gdt_base64", Base64.getEncoder().encodeToString(bytes)));
        } catch (ConnectionException e) { throw e;
        } catch (Exception e) { throw new ConnectionException("BSIM_SIGNATURE_ARCHIVE", 422,
            "Native signature archive could not be exported: " + e.getClass().getSimpleName());
        } finally {
            if (archive != null) archive.close();
            cleanup(directory);
        }
    }

    static Map<String, Object> annotation(Function function) {
        // Read the function record before its signature: a retained FunctionDB
        // refreshes its rolled-back variable cache when its identity is read.
        String name = function.getName();
        Map<String, Object> row = signature(function.getSignature(true));
        row.put("name", name);
        row.put("namespace", namespace(function));
        row.put("namespace_kinds", namespaceKinds(function));
        row.put("custom_storage", function.hasCustomVariableStorage());
        row.put("return_storage", function.getReturn().getVariableStorage().getSerializationString());
        row.put("parameter_storage", Arrays.stream(function.getParameters()).filter(p -> !p.isAutoParameter())
            .map(p -> p.getVariableStorage().getSerializationString()).toList());
        row.put("auto_parameters", Arrays.stream(function.getParameters()).filter(p -> p.isAutoParameter()).map(p -> Map.of(
            "name", p.getName(), "type", p.getDataType().getPathName(),
            "auto_kind", p.getAutoParameterType().toString(), "storage", p.getVariableStorage().getSerializationString())).toList());
        row.put("qualified_name", function.getName(true));
        return row;
    }

    static List<String> namespace(Function function) {
        LinkedList<String> names = new LinkedList<>();
        for (Namespace ns = function.getParentNamespace(); ns != null && !ns.isGlobal(); ns = ns.getParentNamespace()) {
            if (ns instanceof Function || ns.isExternal()) throw invalid("Local or external function namespaces cannot be transferred");
            names.addFirst(ns.getName());
        }
        return List.copyOf(names);
    }

    static List<String> namespaceKinds(Function function) {
        LinkedList<String> kinds = new LinkedList<>();
        for (Namespace ns = function.getParentNamespace(); ns != null && !ns.isGlobal(); ns = ns.getParentNamespace()) {
            kinds.addFirst(ns instanceof ghidra.program.model.listing.GhidraClass ? "class" : "namespace");
        }
        return List.copyOf(kinds);
    }

    static Map<String, Object> signature(ghidra.program.model.listing.FunctionSignature signature) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("return_type", signature.getReturnType().getPathName());
        row.put("calling_convention", signature.getCallingConventionName());
        row.put("varargs", signature.hasVarArgs());
        row.put("noreturn", signature.hasNoReturn());
        row.put("parameters", Arrays.stream(signature.getArguments()).map(p -> Map.of(
            "name", p.getName() == null ? "" : p.getName(), "type", p.getDataType().getPathName())).toList());
        return row;
    }

    static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }

    static void requireBoundedJson(Object value) {
        String json = JSON.toJson(value);
        int bytes = 0;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c <= 0x7f) bytes++;
            else if (c <= 0x7ff) bytes += 2;
            else if (Character.isHighSurrogate(c) && i + 1 < json.length()
                    && Character.isLowSurrogate(json.charAt(i + 1))) { bytes += 4; i++; }
            else bytes += 3;
            if (bytes > MAX_JSON_BYTES) throw oversized();
        }
    }
    static ConnectionException invalid(String message) {
        return new ConnectionException("BSIM_SIGNATURE_INVALID", 422, message);
    }
    static ConnectionException oversized() {
        return new ConnectionException("BSIM_SIGNATURE_TOO_LARGE", 413,
            "Complete signature transport exceeds its bounds (524288 archive bytes, 900000 JSON bytes or 4096 dependency types); truncation is never accepted");
    }

    private static void clearComments(DataType type) {
        if (type instanceof Composite composite) {
            composite.setDescription("");
            for (DataTypeComponent component : composite.getDefinedComponents()) {
                try {
                    COMPONENT_COMMENT.invoke(component, (String) null);
                } catch (ReflectiveOperationException e) {
                    throw invalid("Native datatype component comments could not be removed");
                }
            }
        } else if (type instanceof ghidra.program.model.data.Enum enumeration) {
            enumeration.setDescription("");
            for (String name : enumeration.getNames()) {
                long value = enumeration.getValue(name);
                enumeration.remove(name);
                enumeration.add(name, value);
            }
        } else if (type instanceof FunctionDefinition function) {
            function.setComment(null);
            for (ParameterDefinition parameter : function.getArguments()) parameter.setComment(null);
        }
    }
    static void cleanup(Path directory) {
        if (directory == null) return;
        try (var paths = Files.walk(directory)) {
            for (Path file : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(file);
        } catch (java.io.IOException e) { ghidra.util.Msg.warn(BSimSignatureTransfer.class, "Could not remove temporary signature archive", e); }
    }

    static final class OpenArchive implements AutoCloseable {
        private final Path directory;
        final FileDataTypeManager manager;
        final FunctionDefinition root;
        final List<DataType> types;
        OpenArchive(byte[] bytes, String rootPath, List<String> dependencyRoots) {
            Path temporary = null;
            FileDataTypeManager opened = null;
            try {
                if (bytes.length > MAX_ARCHIVE_BYTES) throw oversized();
                temporary = Files.createTempDirectory("ghydra-signature-read-");
                Path file = temporary.resolve("signature.gdt");
                Files.write(file, bytes);
                opened = FileDataTypeManager.openFileArchive(file.toFile(), false);
                if (!(opened.getDataType(rootPath) instanceof FunctionDefinition definition)) throw invalid("Archive root is not a native function definition");
                List<DataType> all = new ArrayList<>();
                opened.getAllDataTypes().forEachRemaining(all::add);
                if (all.size() > MAX_TYPES) throw oversized();
                Set<DataType> reachable = Collections.newSetFromMap(new IdentityHashMap<>());
                visit(definition, reachable);
                for (String path : dependencyRoots) {
                    DataType dependency = opened.getDataType(path);
                    if (dependency == null) throw invalid("Missing native implicit parameter dependency");
                    visit(dependency, reachable);
                }
                for (DataType type : all) {
                    if (!(type instanceof BuiltInDataType) && !reachable.contains(type)) throw invalid("Archive contains unrelated types");
                }
                directory = temporary;
                manager = opened;
                root = definition;
                types = reachable.stream().filter(t -> t != definition).sorted(Comparator.comparing(DataType::getPathName)).toList();
            } catch (Exception e) {
                if (opened != null) opened.close();
                cleanup(temporary);
                if (e instanceof ConnectionException connection) throw connection;
                throw invalid("Cannot open complete native signature archive: " + e.getClass().getSimpleName());
            }
        }
        public void close() { manager.close(); cleanup(directory); }
    }

    private static void visit(DataType type, Set<DataType> visited) {
        if (type == null) return;
        Deque<DataType> pending = new ArrayDeque<>();
        pending.add(type);
        while (!pending.isEmpty()) {
            DataType current = pending.removeLast();
            // Bitfields are inline component encodings, not named archive entries.
            if (current instanceof BitFieldDataType bitfield) {
                pending.add(bitfield.getBaseDataType());
                continue;
            }
            if (!visited.add(current)) continue;
            if (visited.size() > MAX_TYPES) throw oversized();
            if (current instanceof Pointer pointer) {
                if (pointer.getDataType() != null) pending.add(pointer.getDataType());
            } else if (current instanceof Array array) pending.add(array.getDataType());
            else if (current instanceof TypeDef alias) pending.add(alias.getDataType());
            else if (current instanceof Composite composite) {
                for (DataTypeComponent component : composite.getDefinedComponents()) pending.add(component.getDataType());
            } else if (current instanceof FunctionDefinition function) {
                pending.add(function.getReturnType());
                for (ParameterDefinition argument : function.getArguments()) pending.add(argument.getDataType());
            }
        }
    }

    /** Complete finite graph nodes; references remain paths so recursive definitions are not expanded. */
    static Map<String, Object> describe(DataType type) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("path", type.getPathName()); row.put("kind", kind(type));
        row.put("length", type.getLength()); row.put("alignment", type.getAlignment());
        if (type instanceof Composite composite) {
            row.put("packing", composite.getExplicitPackingValue());
            row.put("minimum_alignment", composite.getExplicitMinimumAlignment());
            row.put("packing_type", composite.getPackingType().toString());
            row.put("alignment_type", composite.getAlignmentType().toString());
            row.put("components", Arrays.stream(composite.getDefinedComponents()).map(c -> {
                Map<String, Object> member = new LinkedHashMap<>();
                member.put("name", c.getFieldName() == null ? "" : c.getFieldName());
                member.put("offset", c.getOffset()); member.put("length", c.getLength());
                member.put("type", c.getDataType().getPathName());
                if (c.getDataType() instanceof BitFieldDataType bitfield) {
                    member.put("base_type", bitfield.getBaseDataType().getPathName());
                    member.put("bit_offset", bitfield.getBitOffset());
                    member.put("bit_size", bitfield.getDeclaredBitSize());
                }
                return member;
            }).toList());
        } else if (type instanceof ghidra.program.model.data.Enum enumeration) {
            row.put("values", Arrays.stream(enumeration.getNames()).map(name -> Map.of("name", name, "value", enumeration.getValue(name))).toList());
        } else if (type instanceof TypeDef alias) row.put("base_type", alias.getDataType().getPathName());
        else if (type instanceof Pointer pointer) row.put("referenced_type", pointer.getDataType() == null ? "" : pointer.getDataType().getPathName());
        else if (type instanceof Array array) { row.put("element_type", array.getDataType().getPathName()); row.put("count", array.getNumElements()); }
        else if (type instanceof BitFieldDataType bitfield) { row.put("base_type", bitfield.getBaseDataType().getPathName()); row.put("bit_offset", bitfield.getBitOffset()); row.put("bit_size", bitfield.getDeclaredBitSize()); }
        else if (type instanceof FunctionDefinition function) row.put("signature", signature(function));
        return row;
    }

    private static String kind(DataType type) {
        if (type instanceof Structure) return "structure";
        if (type instanceof Union) return "union";
        if (type instanceof ghidra.program.model.data.Enum) return "enum";
        if (type instanceof TypeDef) return "typedef";
        if (type instanceof Pointer) return "pointer";
        if (type instanceof Array) return "array";
        if (type instanceof FunctionDefinition) return "function_definition";
        if (type instanceof BitFieldDataType) return "bitfield";
        return type.getClass().getSimpleName();
    }
}
