package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.SymbolDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.PagedCollector;
import eu.starsong.ghidra.util.ProgramCache;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;

/**
 * Service for symbol-related operations.
 */
public class SymbolService {

    /**
     * List one page of symbols matching a filter.
     *
     * <p>The whole symbol table is still walked to count the matches, but only
     * the symbols on the page are turned into DTOs.
     */
    public PagedCollector.Page<SymbolDto> list(Program program, SymbolFilter filter, int offset, int limit) {
        SymbolTable symbolTable = program.getSymbolTable();

        if (filter == null) {
            // The total has to be walked: Ghidra's own symbol counter does not
            // agree with what the iterator yields, and using it would change
            // the meta.total the client sees. The walk is cached per program
            // state, so only the first request pays for it.
            int total = ProgramCache.shared().count(program, "symbols",
                () -> GhidraSwing.runRead(() -> countSymbols(symbolTable)));
            return GhidraSwing.runRead(() -> PagedCollector.collectPage(
                symbolTable.getAllSymbols(true), offset, limit, SymbolDto::from, total));
        }

        Predicate<Symbol> predicate = filter.toPredicate();

        return GhidraSwing.runRead(() -> PagedCollector.collect(
            symbolTable.getAllSymbols(true), predicate, offset, limit, SymbolDto::from));
    }

    /** Counts the symbols the listing walks over. */
    private static int countSymbols(SymbolTable symbolTable) {
        int count = 0;
        for (var it = symbolTable.getAllSymbols(true); it.hasNext(); ) {
            it.next();
            count++;
        }
        return count;
    }

    /**
     * List one page of external/imported symbols.
     */
    public PagedCollector.Page<SymbolDto> listImports(Program program, int offset, int limit) {
        SymbolTable symbolTable = program.getSymbolTable();

        return GhidraSwing.runRead(() -> PagedCollector.collect(
            symbolTable.getExternalSymbols(), sym -> true, offset, limit, SymbolDto::from));
    }

    /**
     * List one page of exported symbols.
     */
    public PagedCollector.Page<SymbolDto> listExports(Program program, int offset, int limit) {
        SymbolTable symbolTable = program.getSymbolTable();

        return GhidraSwing.runRead(() -> PagedCollector.collect(
            symbolTable.getAllSymbols(true),
            sym -> sym.isGlobal() && !sym.isExternal(),
            offset, limit, SymbolDto::from));
    }

    /**
     * Get a symbol by address.
     */
    public Optional<SymbolDto> getByAddress(Program program, String addressStr) {
        return GhidraSwing.runRead(() -> {
            Symbol sym = findByAddress(program, addressStr);
            return Optional.ofNullable(sym).map(SymbolDto::from);
        });
    }

    /**
     * Find raw symbol by address.
     */
    public Symbol findByAddress(Program program, String addressStr) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            return null;
        }
        return program.getSymbolTable().getPrimarySymbol(address);
    }

    /**
     * Rename a symbol.
     */
    public SymbolDto rename(Program program, String addressStr, String newName) throws Exception {
        Symbol symbol = findByAddress(program, addressStr);
        if (symbol == null) {
            throw new NotFoundException("Symbol not found at address: " + addressStr, "SYMBOL_NOT_FOUND");
        }

        TransactionHelper.executeInTransaction(program, "Rename Symbol", () -> {
            GhidraUtil.applyQualifiedName(program, symbol, newName, SourceType.USER_DEFINED);
            return null;
        });

        return GhidraSwing.runRead(() -> {
            return SymbolDto.from(symbol);
        });
    }

    /**
     * Create a label at an address.
     */
    public SymbolDto createLabel(Program program, String addressStr, String name) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        Symbol symbol = TransactionHelper.executeInTransaction(program, "Create Label", () -> {
            return program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
        });

        return GhidraSwing.runRead(() -> {
            return SymbolDto.from(symbol);
        });
    }

    /**
     * Delete a symbol.
     */
    public void delete(Program program, String addressStr) throws Exception {
        Symbol symbol = findByAddress(program, addressStr);
        if (symbol == null) {
            throw new NotFoundException("Symbol not found at address: " + addressStr, "SYMBOL_NOT_FOUND");
        }

        TransactionHelper.executeInTransaction(program, "Delete Symbol", () -> {
            symbol.delete();
            return null;
        });
    }

    // -------------------------------------------------------------------------
    // Filter class
    // -------------------------------------------------------------------------

    public static class SymbolFilter {
        private String nameEquals;
        private String nameContains;
        private String nameMatchesRegex;
        private String type;
        private Boolean isExternal;
        private Boolean isGlobal;

        public SymbolFilter nameEquals(String name) {
            this.nameEquals = name;
            return this;
        }

        public SymbolFilter nameContains(String substring) {
            this.nameContains = substring;
            return this;
        }

        public SymbolFilter nameMatchesRegex(String regex) {
            this.nameMatchesRegex = regex;
            return this;
        }

        public SymbolFilter type(String type) {
            this.type = type;
            return this;
        }

        public SymbolFilter isExternal(Boolean external) {
            this.isExternal = external;
            return this;
        }

        public SymbolFilter isGlobal(Boolean global) {
            this.isGlobal = global;
            return this;
        }

        public static SymbolFilter fromQueryParams(
                String name,
                String nameContains,
                String nameMatchesRegex,
                String type,
                String isExternal,
                String isGlobal) {

            SymbolFilter filter = new SymbolFilter();

            if (name != null && !name.isEmpty()) filter.nameEquals(name);
            if (nameContains != null && !nameContains.isEmpty()) filter.nameContains(nameContains);
            if (nameMatchesRegex != null && !nameMatchesRegex.isEmpty()) filter.nameMatchesRegex(nameMatchesRegex);
            if (type != null && !type.isEmpty()) filter.type(type);
            if (isExternal != null && !isExternal.isEmpty()) filter.isExternal(Boolean.parseBoolean(isExternal));
            if (isGlobal != null && !isGlobal.isEmpty()) filter.isGlobal(Boolean.parseBoolean(isGlobal));

            return filter;
        }

        Predicate<Symbol> toPredicate() {
            List<Predicate<Symbol>> predicates = new ArrayList<>();

            if (nameEquals != null) {
                predicates.add(sym -> sym.getName(true).equals(nameEquals));
            }
            if (nameContains != null) {
                String lower = nameContains.toLowerCase();
                predicates.add(sym -> sym.getName(true).toLowerCase().contains(lower));
            }
            if (nameMatchesRegex != null) {
                Pattern pattern = Pattern.compile(nameMatchesRegex);
                predicates.add(sym -> pattern.matcher(sym.getName(true)).matches());
            }
            if (type != null) {
                predicates.add(sym -> sym.getSymbolType().toString().equalsIgnoreCase(type));
            }
            if (isExternal != null) {
                predicates.add(sym -> sym.isExternal() == isExternal);
            }
            if (isGlobal != null) {
                predicates.add(sym -> sym.isGlobal() == isGlobal);
            }

            return predicates.stream().reduce(sym -> true, Predicate::and);
        }
    }
}
