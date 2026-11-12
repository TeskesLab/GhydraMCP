package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.util.DecompilerCache;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Detached comparison evidence. No transaction, activation, save, or type import occurs. */
public final class BSimFunctionSnapshot {
    private static final int INSTRUCTION_LIMIT = 1000;
    private static final HexFormat INSTRUCTION_HEX = HexFormat.of().withUpperCase();

    private BSimFunctionSnapshot() {}

    public static Map<String, Object> capture(Program program, Function function, int maxCodeLines) {
        if (SwingUtilities.isEventDispatchThread()) throw failure("BSIM_SNAPSHOT_THREAD", 409,
            "Snapshot decompilation must run off the Swing thread");
        if (maxCodeLines < 1 || maxCodeLines > 10000) throw failure("BSIM_SNAPSHOT_INVALID", 400,
            "max_code_lines must be between 1 and 10000");
        Object consumer = new Object();
        boolean pinned = false;
        try {
            pinned = GhidraSwing.runUninterruptibly(() -> {
                if (program == null || program.isClosed() || function == null || function.isDeleted()
                        || function.getProgram() != program) throw changed();
                if (!program.addConsumer(consumer)) throw changed();
                return true;
            });
            Map<String, Object> snapshot = GhidraSwing.runUninterruptibly(
                () -> GhidraSwing.runRead(() -> describe(program, function)));
            long stamp = ((Number) snapshot.get("modification")).longValue();
            snapshot.put("code", decompile(program, function, maxCodeLines));
            GhidraSwing.runUninterruptibly(() -> GhidraSwing.runRead(() -> {
                if (program.isClosed() || function.isDeleted() || program.getModificationNumber() != stamp) {
                    throw changed();
                }
                return null;
            }));
            return snapshot;
        } catch (ConnectionException e) {
            throw e;
        } catch (RuntimeException e) {
            // Swing wrappers and native database failures must not leak endpoint/path details.
            throw failure("BSIM_SNAPSHOT_FAILED", 409, "Consistent function evidence could not be captured");
        } finally {
            if (pinned) program.release(consumer);
        }
    }

    public static String qualifiedAddress(Address address) {
        return address.getAddressSpace().getName() + "::0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    private static Map<String, Object> describe(Program program, Function function) {
        long stamp = program.getModificationNumber();
        TypeGraph graph = new TypeGraph();
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("name", program.getName());
        p.put("md5", program.getExecutableMD5());
        p.put("language", program.getLanguageID().toString());
        p.put("compiler", program.getCompilerSpec().getCompilerSpecID().toString());
        p.put("pointer_size", program.getDefaultPointerSize());
        if (program.getDomainFile() != null) {
            p.put("version", program.getDomainFile().getVersion());
            p.put("path", program.getDomainFile().getPathname());
        }
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("name", function.getName(true));
        f.put("address", qualifiedAddress(function.getEntryPoint()));
        f.put("prototype", function.getPrototypeString(false, true));
        f.put("calling_convention", function.getCallingConventionName());
        f.put("varargs", function.hasVarArgs());
        f.put("return_type", graph.id(function.getReturnType(), 0));
        List<Map<String, Object>> parameters = new ArrayList<>();
        for (Parameter parameter : function.getParameters()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("ordinal", parameter.getOrdinal());
            row.put("name", parameter.getName());
            row.put("type", graph.id(parameter.getDataType(), 0));
            parameters.add(row);
        }
        f.put("parameters", parameters);
        f.put("comment", function.getComment());
        Map<String, Object> instructions = instructions(program, function);
        if (stamp != program.getModificationNumber()) throw changed();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", p);
        result.put("function", f);
        result.put("types", graph.descriptors);
        result.put("types_complete", graph.complete);
        result.put("instructions", instructions);
        result.put("modification", stamp);
        return result;
    }

    /** Listing traversal and detached row construction share describe's EDT/stamp boundary. */
    private static Map<String, Object> instructions(Program program, Function function) {
        List<Map<String, Object>> rows = new ArrayList<>();
        long bodyBytes = 0;
        long decodedBytes = 0;
        String error = null;
        try {
            AddressSetView body = function.getBody();
            bodyBytes = body.getNumAddresses();
            InstructionIterator iterator = program.getListing().getInstructions(body, true);
            while (iterator.hasNext()) {
                // One lookahead only; never walk the remainder of an oversized function.
                if (rows.size() == INSTRUCTION_LIMIT) {
                    error = "Native instruction count exceeds limit";
                    break;
                }
                Instruction instruction = iterator.next();
                Address start = instruction.getMinAddress();
                int length = instruction.getLength();
                if (length < 1 || instruction.getParsedLength() != length) {
                    error = "Native instruction length override or unsupported decoding";
                    break;
                }
                if (!body.contains(start, instruction.getMaxAddress())) {
                    error = "Native instruction crosses function body";
                    break;
                }
                // Read memory directly, not the CodeUnit byte cache: a native memory failure
                // must not become apparently complete evidence from previously cached bytes.
                byte[] bytes = new byte[length];
                if (program.getMemory().getBytes(start, bytes) != length) {
                    error = "Native instruction memory could not be read completely";
                    break;
                }
                String mnemonic = instruction.getMnemonicString();
                List<String> operands = new ArrayList<>();
                List<Integer> operandTypes = new ArrayList<>();
                for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                    String text = instruction.getDefaultOperandRepresentation(operand);
                    if (text == null) throw new IllegalStateException("Missing native operand");
                    operands.add(text);
                    operandTypes.add(instruction.getOperandType(operand));
                }
                if (mnemonic == null || mnemonic.isBlank()) {
                    error = "Native instruction mnemonic is unavailable";
                    break;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", qualifiedAddress(start));
                row.put("mnemonic", mnemonic);
                row.put("operands", operands);
                row.put("operand_types", operandTypes);
                row.put("bytes", INSTRUCTION_HEX.formatHex(bytes));
                row.put("length", length);
                rows.add(row);
                decodedBytes += length;
            }
            // Native listing instructions do not overlap, so equal covered byte counts prove
            // full coverage even for disjoint bodies, without iterating body bytes or ranges.
            if (error == null && (rows.isEmpty() || decodedBytes != bodyBytes)) {
                error = "Function body contains undefined or missing native instructions";
            }
        } catch (MemoryAccessException e) {
            error = "Native instruction memory could not be read";
        } catch (RuntimeException | LinkageError e) {
            error = "Native instruction evidence is unavailable";
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rows", rows);
        result.put("complete", error == null);
        result.put("error", error);
        result.put("limit", INSTRUCTION_LIMIT);
        result.put("body_bytes", bodyBytes);
        result.put("decoded_bytes", decodedBytes);
        return result;
    }

    private static Map<String, Object> decompile(Program program, Function function, int maxLines) {
        String text = null;
        String error = null;
        boolean complete = false;
        try {
            DecompileResults results = DecompilerCache.shared().getDecompileResults(program, function, 60);
            if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
                text = results.getDecompiledFunction().getC();
            }
            if (text == null || text.isBlank()) {
                text = null;
                error = "Decompilation did not produce code";
            } else {
                complete = true;
                int lines = 0;
                for (int i = 0; i < text.length(); i++) {
                    if (text.charAt(i) == '\n' && ++lines == maxLines && i + 1 < text.length()) {
                        text = text.substring(0, i + 1);
                        complete = false;
                        error = "Decompiled code exceeds max_code_lines";
                        break;
                    }
                }
            }
        } catch (RuntimeException | LinkageError e) {
            error = "Decompilation is unavailable";
        }
        Map<String, Object> code = new LinkedHashMap<>();
        code.put("text", text);
        code.put("complete", complete);
        code.put("error", error);
        return code;
    }

    private static ConnectionException changed() {
        return failure("BSIM_SNAPSHOT_CHANGED", 409, "Program or function changed during evidence capture");
    }

    private static ConnectionException failure(String code, int status, String reason) {
        return new ConnectionException(code, status, reason);
    }

    /** IDs are local to one graph, with references inserted before recursively describing shape. */
    private static final class TypeGraph {
        final IdentityHashMap<DataType, String> ids = new IdentityHashMap<>();
        final Map<String, Object> descriptors = new LinkedHashMap<>();
        boolean complete = true;
        int componentsLeft = 4096;

        String id(DataType type, int depth) {
            if (type == null) { complete = false; return null; }
            String existing = ids.get(type);
            if (existing != null) return existing;
            if (depth > 16 || ids.size() >= 256) { complete = false; return null; }
            String id = "t" + ids.size();
            ids.put(type, id);
            Map<String, Object> row = new LinkedHashMap<>();
            descriptors.put(id, row);
            row.put("kind", kind(type));
            row.put("name", type.getName());
            row.put("path", type.getPathName());
            row.put("length", type.getLength());
            if (type instanceof Pointer pointer) {
                row.put("target", id(pointer.getDataType(), depth + 1));
            } else if (type instanceof Array array) {
                row.put("element", id(array.getDataType(), depth + 1));
                row.put("count", array.getNumElements());
            } else if (type instanceof TypeDef alias) {
                row.put("base", id(alias.getDataType(), depth + 1));
            } else if (type instanceof BitFieldDataType bits) {
                row.put("base", id(bits.getBaseDataType(), depth + 1));
                row.put("bit_offset", bits.getBitOffset());
                row.put("bit_size", bits.getDeclaredBitSize());
            } else if (type instanceof ghidra.program.model.data.Enum enumeration) {
                Map<String, Object> values = new LinkedHashMap<>();
                for (String name : enumeration.getNames()) {
                    if (componentsLeft-- <= 0) { complete = false; break; }
                    values.put(name, enumeration.getValue(name));
                }
                row.put("values", values);
            } else if (type instanceof Composite composite) {
                List<Map<String, Object>> components = new ArrayList<>();
                for (int index = 0; index < composite.getNumComponents(); index++) {
                    if (componentsLeft-- <= 0) { complete = false; break; }
                    DataTypeComponent component = composite.getComponent(index);
                    Map<String, Object> field = new LinkedHashMap<>();
                    field.put("name", component.getFieldName());
                    field.put("offset", component.getOffset());
                    field.put("length", component.getLength());
                    field.put("type", id(component.getDataType(), depth + 1));
                    field.put("bitfield", component.isBitFieldComponent());
                    if (component.getDataType() instanceof BitFieldDataType bits) {
                        field.put("bit_offset", bits.getBitOffset());
                        field.put("bit_size", bits.getDeclaredBitSize());
                    }
                    components.add(field);
                }
                row.put("components", components);
            } else if (type instanceof FunctionDefinition definition) {
                row.put("return_type", id(definition.getReturnType(), depth + 1));
                row.put("calling_convention", definition.getCallingConventionName());
                row.put("varargs", definition.hasVarArgs());
                List<Map<String, Object>> args = new ArrayList<>();
                for (ParameterDefinition parameter : definition.getArguments()) {
                    if (componentsLeft-- <= 0) { complete = false; break; }
                    Map<String, Object> arg = new LinkedHashMap<>();
                    arg.put("ordinal", parameter.getOrdinal());
                    arg.put("name", parameter.getName());
                    arg.put("type", id(parameter.getDataType(), depth + 1));
                    args.add(arg);
                }
                row.put("parameters", args);
            }
            return id;
        }

        private String kind(DataType type) {
            if (type instanceof Pointer) return "pointer";
            if (type instanceof Array) return "array";
            if (type instanceof TypeDef) return "typedef";
            if (type instanceof BitFieldDataType) return "bitfield";
            if (type instanceof ghidra.program.model.data.Enum) return "enum";
            if (type instanceof Structure) return "struct";
            if (type instanceof Union) return "union";
            if (type instanceof FunctionDefinition) return "function_definition";
            if (type instanceof BuiltInDataType) return "builtin";
            complete = false;
            return "unknown";
        }
    }
}
