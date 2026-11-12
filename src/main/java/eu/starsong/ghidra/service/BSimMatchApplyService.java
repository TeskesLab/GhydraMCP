package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.server.ManagedProgramGuard;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

/**
 * Explicit, single-use exact-row application. Never queries BSim or opens a source endpoint.
 * The authenticated coordinator must fetch the export directly from its approved reference worker.
 * This service checks selection consistency and applicability, not forwarded-archive provenance.
 */
public final class BSimMatchApplyService {
    private static final int CAPACITY = 32;
    private static final long LIFETIME_NANOS = java.util.concurrent.TimeUnit.MINUTES.toNanos(5);
    private final BSimMatchService matches;
    private final java.util.function.LongSupplier clock;
    private final Map<String, Prepared> prepared = new LinkedHashMap<>();
    private record Prepared(String matchId, BSimMatchService.Selection selection, byte[] archive,
            String root, List<String> dependencyRoots, String name, List<String> namespace,
            List<String> namespaceKinds, Map<String, Object> preview, long created) {}

    public BSimMatchApplyService(BSimMatchService matches) { this(matches, System::nanoTime); }
    BSimMatchApplyService(BSimMatchService matches, java.util.function.LongSupplier clock) {
        this.matches = matches;
        this.clock = clock;
    }

    public Map<String, Object> prepare(Program program, String id, Map<?, ?> reference) {
        return prepare(program, id, reference, () -> program);
    }

    public Map<String, Object> prepare(Program program, String id, Map<?, ?> reference,
            java.util.function.Supplier<Program> activeProgram) {
        BSimMatchService.Selection selected = matches.require(program, id);
        if (reference == null || !Boolean.TRUE.equals(reference.get("identity_verified"))
                || !id.equals(reference.get("match_id"))) throw invalid("Reference is not the exact selected export");
        BSimSignatureTransfer.requireBoundedJson(reference);
        Map<?, ?> identity = object(reference, "identity");
        Map<String, Object> row = selected.match();
        if (!Objects.equals(row.get("repository_url"), identity.get("repository_url"))
                || !(row.get("executable_md5") instanceof String md5)
                || !md5.equalsIgnoreCase(text(identity, "executable_md5"))
                || !Objects.equals(row.get("address"), identity.get("selected_address"))
                || !sameCoordinate(text(row, "address"), text(identity, "address"))
                || !Objects.equals(row.getOrDefault("function", ""), identity.get("indexed_function"))) {
            throw invalid("Export identity does not match the immutable selected row");
        }
        int version = positiveInteger(reference, "version");
        String referenceProfile = text(reference, "profile");
        String path = text(reference, "path");
        Map<?, ?> abiFields = object(reference, "abi");
        Map<String, Object> sourceAbi = Map.of("language", text(abiFields, "language"),
            "compiler", text(abiFields, "compiler"), "pointer_size", positiveInteger(abiFields, "pointer_size"));
        Map<?, ?> function = object(reference, "function");
        String name = text(function, "name");
        List<String> namespace = namespace(function.get("namespace"));
        List<String> namespaceKinds = namespaceKinds(function.get("namespace_kinds"), namespace.size());
        List<Map<String, Object>> autoParameters = autoParameters(function.get("auto_parameters"));
        Storage storage = storage(function);
        Map<?, ?> archive = object(reference, "archive");
        if (!"ghidra-gdt-v1".equals(archive.get("format"))) throw invalid("Unsupported native archive format");
        String root = text(archive, "root_type");
        List<String> dependencyRoots = paths(archive.get("dependency_roots"));
        if (!new HashSet<>(dependencyRoots).equals(autoParameters.stream().map(p -> (String) p.get("type")).collect(java.util.stream.Collectors.toSet()))) {
            throw invalid("Implicit parameter dependency roots disagree with the native annotation");
        }
        String encoded = text(archive, "gdt_base64");
        if (encoded.length() > ((BSimSignatureTransfer.MAX_ARCHIVE_BYTES + 2) / 3) * 4) throw BSimSignatureTransfer.oversized();
        byte[] bytes;
        try { bytes = Base64.getDecoder().decode(encoded); }
        catch (IllegalArgumentException e) { throw invalid("Native archive is not valid Base64"); }
        if (bytes.length > BSimSignatureTransfer.MAX_ARCHIVE_BYTES) throw BSimSignatureTransfer.oversized();
        if (positiveInteger(archive, "size") != bytes.length
                || !BSimSignatureTransfer.digest(bytes).equals(text(archive, "sha256"))) throw invalid("Native archive size or digest mismatch");
        Map<String, Object> preview;
        try (var nativeArchive = new BSimSignatureTransfer.OpenArchive(bytes, root, dependencyRoots)) {
            preview = GhidraSwing.runRead(() -> {
                BSimMatchService.check(program, selected);
                requireActive(program, activeProgram);
                if (!BSimSignatureTransfer.abi(program).equals(sourceAbi)
                        || nativeArchive.manager.getProgramArchitecture() == null
                        || !program.getLanguageID().equals(nativeArchive.manager.getProgramArchitecture().getLanguage().getLanguageID())
                        || !program.getCompilerSpec().getCompilerSpecID().equals(nativeArchive.manager.getProgramArchitecture().getCompilerSpec().getCompilerSpecID())
                        || program.getDefaultPointerSize() != nativeArchive.manager.getDataOrganization().getPointerSize()) {
                    throw new ConnectionException("BSIM_SIGNATURE_ABI", 409, "Source and target language, compiler and pointer size must match exactly");
                }
                Function target = target(program, selected);
                validateConvention(program, nativeArchive.root);
                validateConflicts(program, nativeArchive);
                validateNamespaces(program, namespace, namespaceKinds);
                Map<String, Object> after = validateNativeImport(program, nativeArchive, name, namespace, namespaceKinds, storage);
                if (!after.equals(function) || !after.get("auto_parameters").equals(autoParameters)) {
                    throw invalid("Source annotation or implicit ABI parameters disagree with the native signature");
                }
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("before", BSimSignatureTransfer.annotation(target));
                result.put("after", after);
                result.put("types", proposals(program, nativeArchive));
                result.put("reference", Map.of("identity", Map.of(
                    "repository_url", text(identity, "repository_url"), "executable_md5", text(identity, "executable_md5"),
                    "address", text(identity, "address"), "selected_address", text(identity, "selected_address"),
                    "indexed_function", String.valueOf(identity.get("indexed_function"))), "profile", referenceProfile,
                    "path", path, "version", version));
                result.put("abi", BSimSignatureTransfer.abi(program));
                result.put("comments_transferred", false);
                result.put("selection_identity_checked", true);
                result.put("archive_sha256", BSimSignatureTransfer.digest(bytes));
                BSimMatchService.check(program, selected);
                BSimSignatureTransfer.requireBoundedJson(result);
                return immutable(result);
            });
        }
        String token = UUID.randomUUID().toString();
        synchronized (prepared) {
            prepared.entrySet().removeIf(entry -> expired(entry.getValue()));
            prepared.put(token, new Prepared(id, selected, bytes, root, dependencyRoots, name, namespace, namespaceKinds, preview, clock.getAsLong()));
            while (prepared.size() > CAPACITY) prepared.remove(prepared.keySet().iterator().next());
        }
        return Map.of("prepared", true, "applied", false, "match_id", id, "apply_token", token,
            "expires_in_seconds", 300, "preview", preview);
    }

    public Map<String, Object> apply(Program program, String id, String token) {
        return apply(program, id, token, () -> program);
    }

    public Map<String, Object> apply(Program program, String id, String token,
            java.util.function.Supplier<Program> activeProgram) {
        if (token == null || token.isBlank()) throw tokenFailure();
        Prepared proposal;
        // Atomic consumption precedes native work, so competing requests cannot apply twice.
        synchronized (prepared) { proposal = prepared.remove(token); }
        if (proposal == null || expired(proposal) || !proposal.matchId().equals(id)) throw tokenFailure();
        BSimMatchService.Selection selected = matches.require(program, id);
        if (selected != proposal.selection()) throw tokenFailure();
        try (var archive = new BSimSignatureTransfer.OpenArchive(proposal.archive(), proposal.root(), proposal.dependencyRoots())) {
            return GhidraSwing.runRead(() -> {
                BSimMatchService.check(program, selected);
                requireActive(program, activeProgram);
                ManagedProgramGuard.validateMutation(program);
                // Success must mean our own commit, not an uncommitted nested outer transaction.
                if (program.getCurrentTransactionInfo() != null) throw new ConnectionException(
                    "BSIM_APPLY_BUSY", 409, "Finish the active native transaction and prepare again");
                return TransactionHelper.executeInTransaction(program, "Apply explicitly selected BSim signature", () -> {
                    BSimMatchService.check(program, selected);
                    requireActive(program, activeProgram);
                    if (!BSimSignatureTransfer.abi(program).equals(proposal.preview().get("abi"))) throw invalid("Target ABI changed");
                    validateConflicts(program, archive);
                    Function function = target(program, selected);
                    applyDefinition(program, function, archive, proposal.name(), proposal.namespace(), proposal.namespaceKinds(),
                        storage((Map<?, ?>) proposal.preview().get("after")));
                    // Native APIs can normalize unsupported inputs; never claim an exact apply then.
                    if (!BSimSignatureTransfer.annotation(function).equals(proposal.preview().get("after"))) {
                        throw invalid("Native target could not represent the exact prepared signature");
                    }
                    validateImported(program, archive);
                    return Map.<String, Object>of("applied", true, "match_id", id, "summary", proposal.preview());
                });
            });
        }
    }

    private static Map<String, Object> validateNativeImport(Program program,
            BSimSignatureTransfer.OpenArchive archive, String name, List<String> namespace, List<String> kinds, Storage storage) throws Exception {
        // A private native database verifies both type import and dynamic ABI/hidden parameters.
        // Nothing, including namespaces or transient data types, is added to the active target.
        Object owner = new Object();
        // DB.jar is runtime-provided, absent from the baseline compile SDK.
        // Resolve the native implementation without linking its DB-only interfaces.
        Program scratch = (Program) Class.forName("ghidra.program.database.ProgramDB")
            .getConstructor(String.class, ghidra.program.model.lang.Language.class,
                ghidra.program.model.lang.CompilerSpec.class, Object.class)
            .newInstance("BSim signature preview", program.getLanguage(),
                program.getLanguage().getCompilerSpecByID(program.getCompilerSpec().getCompilerSpecID()), owner);
        try {
            return TransactionHelper.executeInTransaction(scratch, "Validate complete signature in isolated native program", () -> {
                for (DataType type : archive.types) {
                    DataType existing = program.getDataTypeManager().getDataType(type.getPathName());
                    if (existing != null) scratch.getDataTypeManager().resolve(existing, STRICT);
                }
                var address = scratch.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                Function function = scratch.getFunctionManager().createFunction("preview", address,
                    new ghidra.program.model.address.AddressSet(address), SourceType.USER_DEFINED);
                applyDefinition(scratch, function, archive, name, namespace, kinds, storage);
                validateImported(scratch, archive);
                return BSimSignatureTransfer.annotation(function);
            });
        } finally { scratch.release(owner); }
    }

    private static void applyDefinition(Program program, Function function,
            BSimSignatureTransfer.OpenArchive archive, String name, List<String> names, List<String> kinds, Storage storage) throws Exception {
        DataTypeManager manager = program.getDataTypeManager();
        for (DataType type : archive.types) resolve(manager, type);
        Namespace namespace = program.getGlobalNamespace();
        for (int index = 0; index < names.size(); index++) {
            String component = names.get(index);
            boolean classNamespace = "class".equals(kinds.get(index));
            Namespace existing = program.getSymbolTable().getNamespace(component, namespace);
            if (existing != null && (existing instanceof Function || existing.isExternal()
                    || (existing instanceof GhidraClass) != classNamespace)) throw invalid("Incompatible target namespace kind");
            namespace = existing != null ? existing : classNamespace
                ? program.getSymbolTable().createClass(namespace, component, SourceType.USER_DEFINED)
                : program.getSymbolTable().createNameSpace(namespace, component, SourceType.USER_DEFINED);
        }
        function.setParentNamespace(namespace);
        function.setName(name, SourceType.USER_DEFINED);
        if (storage.parameters().size() != archive.root.getArguments().length) throw invalid("Parameter storage count disagrees with native signature");
        List<Variable> parameters = new ArrayList<>();
        int ordinal = 0;
        for (ParameterDefinition argument : archive.root.getArguments()) {
            DataType type = resolve(manager, argument.getDataType());
            parameters.add(storage.custom()
                ? new ParameterImpl(argument.getName(), type, deserialize(program, storage.parameters().get(ordinal)), program, SourceType.USER_DEFINED)
                : new ParameterImpl(argument.getName(), type, program, SourceType.USER_DEFINED));
            ordinal++;
        }
        DataType returnType = resolve(manager, archive.root.getReturnType());
        function.updateFunction(archive.root.getCallingConventionName(), storage.custom()
                ? new ReturnParameterImpl(returnType, deserialize(program, storage.result()), program)
                : new ReturnParameterImpl(returnType, program), parameters,
            storage.custom() ? Function.FunctionUpdateType.CUSTOM_STORAGE
                : Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED);
        function.setVarArgs(archive.root.hasVarArgs());
        function.setNoReturn(archive.root.hasNoReturn());
    }

    private static void validateConflicts(Program program, BSimSignatureTransfer.OpenArchive archive) {
        for (DataType type : archive.types) {
            DataType existing = program.getDataTypeManager().getDataType(type.getPathName());
            if (existing != null && !equivalent(type, existing)) throw conflict(type);
            if (type.getUniversalID() != null) {
                DataType associated = program.getDataTypeManager().findDataTypeForID(type.getUniversalID());
                if (associated != null && (!associated.getPathName().equals(type.getPathName()) || !equivalent(type, associated))) throw conflict(type);
            }
        }
    }

    private static void validateImported(Program program, BSimSignatureTransfer.OpenArchive archive) {
        for (DataType type : archive.types) {
            DataType imported = program.getDataTypeManager().getDataType(type.getPathName());
            if (imported == null || !equivalent(type, imported)) throw conflict(type);
        }
    }

    private static boolean equivalent(DataType left, DataType right) {
        // Structural descriptions prevent native source-ID equivalence from hiding a changed layout.
        return left.isEquivalent(right) && BSimSignatureTransfer.describe(left).equals(BSimSignatureTransfer.describe(right));
    }

    private static List<Map<String, Object>> proposals(Program program, BSimSignatureTransfer.OpenArchive archive) {
        return archive.types.stream().map(type -> {
            Map<String, Object> row = BSimSignatureTransfer.describe(type);
            row.put("action", program.getDataTypeManager().getDataType(type.getPathName()) == null ? "import" : "reuse_equivalent");
            return row;
        }).toList();
    }

    private static final DataTypeConflictHandler STRICT = new DataTypeConflictHandler() {
        public ConflictResult resolveConflict(DataType added, DataType existing) {
            if (!equivalent(added, existing)) throw conflict(added);
            return ConflictResult.USE_EXISTING;
        }
        public boolean shouldUpdate(DataType source, DataType local) { return false; }
        public DataTypeConflictHandler getSubsequentHandler() { return this; }
    };
    private static DataType resolve(DataTypeManager manager, DataType type) {
        DataType resolved = manager.resolve(type, STRICT);
        if (!resolved.getPathName().equals(type.getPathName()) || !equivalent(type, resolved)) throw conflict(type);
        return resolved;
    }

    private static void validateConvention(Program program, FunctionDefinition root) {
        String convention = root.getCallingConventionName();
        if (convention != null && !Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention)
                && !Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention)
                && program.getCompilerSpec().getCallingConvention(convention) == null) throw invalid("Unsupported source calling convention");
        Set<String> names = new HashSet<>();
        for (ParameterDefinition parameter : root.getArguments()) {
            if (parameter.getName() != null && !parameter.getName().isBlank() && !names.add(parameter.getName())) throw invalid("Duplicate source parameter names");
        }
    }

    private static Function target(Program program, BSimMatchService.Selection selected) {
        Function function = program.getFunctionManager().getFunctionAt(GhidraUtil.resolveAddress(program, selected.address(), false));
        if (function == null) throw new ConnectionException("BSIM_MATCH_STALE", 409, "Selected target function no longer exists; query and prepare again");
        return function;
    }
    private static boolean sameCoordinate(String selected, String exported) {
        String[] a = selected.split("::", -1), b = exported.split("::", -1);
        if (a.length > 2 || b.length != 2 || (a.length == 2 && !a[0].equals(b[0]))) return false;
        try { return Long.parseUnsignedLong(a[a.length - 1].replaceFirst("^0[xX]", ""), 16)
            == Long.parseUnsignedLong(b[1].replaceFirst("^0[xX]", ""), 16); }
        catch (NumberFormatException e) { return false; }
    }
    private static List<String> namespace(Object value) {
        if (!(value instanceof List<?> components) || components.size() > 128) throw invalid("Invalid source namespace");
        List<String> result = new ArrayList<>();
        for (Object component : components) {
            if (!(component instanceof String name) || name.isBlank() || name.contains("::") || name.length() > 1024) throw invalid("Invalid source namespace component");
            result.add(name);
        }
        return List.copyOf(result);
    }
    private static String qualified(List<String> namespace, String name) { return namespace.isEmpty() ? name : String.join("::", namespace) + "::" + name; }
    private boolean expired(Prepared proposal) { return clock.getAsLong() - proposal.created() > LIFETIME_NANOS; }
    private static void requireActive(Program program, java.util.function.Supplier<Program> activeProgram) {
        if (activeProgram.get() != program) throw new ConnectionException("BSIM_MATCH_STALE", 409,
            "The active target changed; query and prepare a fresh preview");
    }
    private record Storage(boolean custom, String result, List<String> parameters) {}
    private static Storage storage(Map<?, ?> function) {
        if (!(function.get("custom_storage") instanceof Boolean custom)) throw invalid("Missing native storage mode");
        String result = text(function, "return_storage");
        if (result.length() > 8192) throw invalid("Return storage description exceeds native bounds");
        return new Storage(custom, result, paths(function.get("parameter_storage")));
    }
    private static VariableStorage deserialize(Program program, String value) throws Exception {
        VariableStorage storage = VariableStorage.deserialize(program, value);
        if (storage.isBadStorage() || storage.getVarnodeCount() > 64) throw invalid("Unrepresentable native variable storage");
        return storage;
    }

    private static List<String> namespaceKinds(Object value, int size) {
        List<String> kinds = paths(value);
        if (kinds.size() != size || kinds.stream().anyMatch(kind -> !Set.of("class", "namespace").contains(kind))) throw invalid("Invalid native namespace kinds");
        return kinds;
    }
    private static List<String> paths(Object value) {
        if (!(value instanceof List<?> list) || list.size() > 4096) throw invalid("Invalid native dependency list");
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof String text) || text.isBlank() || text.length() > 8192) throw invalid("Invalid native dependency path");
            result.add(text);
        }
        return List.copyOf(result);
    }
    private static List<Map<String, Object>> autoParameters(Object value) {
        if (!(value instanceof List<?> list) || list.size() > 16) throw invalid("Invalid implicit parameter metadata");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map) || !map.keySet().equals(Set.of("name", "type", "auto_kind", "storage"))) throw invalid("Invalid implicit parameter annotation");
            result.add(Map.of("name", text(map, "name"), "type", text(map, "type"),
                "auto_kind", text(map, "auto_kind"), "storage", text(map, "storage")));
        }
        return List.copyOf(result);
    }
    private static void validateNamespaces(Program program, List<String> names, List<String> kinds) {
        Namespace namespace = program.getGlobalNamespace();
        for (int i = 0; i < names.size(); i++) {
            namespace = program.getSymbolTable().getNamespace(names.get(i), namespace);
            if (namespace == null) return;
            if (namespace instanceof Function || namespace.isExternal()
                    || (namespace instanceof GhidraClass) != "class".equals(kinds.get(i))) throw invalid("Incompatible target namespace kind");
        }
    }
    @SuppressWarnings("unchecked")
    private static <T> T immutable(T value) {
        if (value instanceof Map<?, ?> map) {
            Map<Object, Object> result = new LinkedHashMap<>();
            map.forEach((key, child) -> result.put(key, immutable(child)));
            return (T) Collections.unmodifiableMap(result);
        }
        if (value instanceof List<?> list) return (T) list.stream().map(BSimMatchApplyService::immutable).toList();
        return value;
    }
    private static Map<?, ?> object(Map<?, ?> map, String key) {
        if (!(map.get(key) instanceof Map<?, ?> value)) throw invalid("Missing " + key + " object");
        return value;
    }
    private static String text(Map<?, ?> map, String key) {
        if (!(map.get(key) instanceof String value) || value.isBlank()) throw invalid("Missing " + key);
        return value;
    }
    private static int positiveInteger(Map<?, ?> map, String key) {
        if (!(map.get(key) instanceof Number value) || value.intValue() < 1 || value.doubleValue() != value.intValue()) throw invalid("Invalid " + key);
        return value.intValue();
    }
    private static ConnectionException invalid(String message) { return BSimSignatureTransfer.invalid(message); }
    private static ConnectionException conflict(DataType type) { return new ConnectionException("BSIM_SIGNATURE_TYPE_CONFLICT", 409,
        "Incompatible existing native datatype: " + type.getPathName() + "; no unrelated type will be overwritten"); }
    private static ConnectionException tokenFailure() { return new ConnectionException("BSIM_APPLY_TOKEN", 409,
        "Unknown, expired, consumed or mismatched apply token; query and prepare a fresh preview"); }
}
