package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.ClassDto;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.PagedCollector;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Lookups for classes and namespaces derived from the symbol table.
 */
public class NamespaceService {

    /**
     * List one page of classes.
     *
     * <p>The symbol table still has to be walked to find the class names, but
     * only the names on the page become DTOs.
     */
    public PagedCollector.Page<ClassDto> listClasses(Program program, int offset, int limit) {
        return GhidraSwing.runRead(() -> {
            Set<String> classNames = new HashSet<>();
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !ns.isGlobal() && ns.getSymbol().getSymbolType().isNamespace()) {
                    classNames.add(ns.getName(true));
                }
            }
            List<String> sorted = new ArrayList<>(classNames);
            Collections.sort(sorted);
            return PagedCollector.collect(sorted.iterator(), name -> true, offset, limit,
                ClassDto::fromQualifiedName);
        });
    }

    /**
     * List one page of namespaces.
     */
    public PagedCollector.Page<String> listNamespaces(Program program, int offset, int limit) {
        return GhidraSwing.runRead(() -> {
            Set<String> namespaces = new HashSet<>();
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !(ns instanceof GlobalNamespace)) {
                    namespaces.add(ns.getName(true));
                }
            }
            List<String> sorted = new ArrayList<>(namespaces);
            Collections.sort(sorted);
            return PagedCollector.collect(sorted.iterator(), name -> true, offset, limit, name -> name);
        });
    }
}
