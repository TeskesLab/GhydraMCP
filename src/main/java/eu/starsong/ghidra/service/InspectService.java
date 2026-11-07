package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.AddressContextDto;
import eu.starsong.ghidra.dto.DataDto;
import eu.starsong.ghidra.dto.DisassemblyInstructionDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.SymbolDto;
import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.List;

/**
 * Service for answering "what is at this address" in one call.
 *
 * <p>The pieces were all there — the symbol, the containing function, the
 * data, the instruction, the comments and the references — but an agent had
 * to know which endpoint holds each one and pay a round trip for each. This
 * service gathers them in a single read.
 */
public class InspectService {

    /** Cap on the references returned per side, so one hot address cannot flood the answer. */
    private static final int MAX_XREFS = 200;

    /**
     * Describe an address: what is called there, what holds it, what refers to it.
     *
     * <p>The whole traversal and every DTO construction happen inside one
     * {@link GhidraSwing#runRead}: the reads and the DTOs have to see the
     * same state, and the DB is only safe to walk under the EDT.
     */
    public AddressContextDto context(Program program, String addressStr) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        return GhidraSwing.runRead(() -> {
            Listing listing = program.getListing();

            Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
            Function function = program.getFunctionManager().getFunctionContaining(address);
            Data data = listing.getDataAt(address);
            Instruction instruction = listing.getInstructionAt(address);

            String comment = listing.getComment(CommentType.PLATE, address);
            String eolComment = listing.getComment(CommentType.EOL, address);

            List<XrefDto> xrefsTo = referencesTo(program, address);
            List<XrefDto> xrefsFrom = referencesFrom(program, address);

            return new AddressContextDto(
                address.toString(),
                address.getAddressSpace().getName(),
                SymbolDto.from(symbol),
                FunctionSummaryDto.from(function),
                DataDto.from(data),
                instruction == null ? null : DisassemblyInstructionDto.from(instruction, program),
                comment,
                eolComment,
                xrefsTo,
                xrefsFrom);
        });
    }

    private List<XrefDto> referencesTo(Program program, Address address) {
        List<XrefDto> refs = new ArrayList<>();
        var iterator = program.getReferenceManager().getReferencesTo(address);
        while (iterator.hasNext() && refs.size() < MAX_XREFS) {
            refs.add(XrefDto.from(iterator.next(), program));
        }
        return refs;
    }

    private List<XrefDto> referencesFrom(Program program, Address address) {
        List<XrefDto> refs = new ArrayList<>();
        for (Reference ref : program.getReferenceManager().getReferencesFrom(address)) {
            if (refs.size() >= MAX_XREFS) {
                break;
            }
            refs.add(XrefDto.from(ref, program));
        }
        return refs;
    }
}
