package eu.starsong.ghidra.dto;

import java.util.List;

/**
 * Everything one address holds, in a single answer.
 *
 * <p>An agent that lands on an address has to ask four questions: what is
 * called here, what function is it in, what data does it hold, and who
 * refers to it. This record is the answer to all four, so the cost of
 * arriving at an address is one call instead of four.
 *
 * <p>Every field but the address may be null: an address in the middle of
 * nowhere has no symbol, no data and no instruction.
 */
public record AddressContextDto(
    String address,
    String addressSpace,
    SymbolDto symbol,
    FunctionSummaryDto function,
    DataDto data,
    DisassemblyInstructionDto instruction,
    String comment,
    String eolComment,
    List<XrefDto> xrefsTo,
    List<XrefDto> xrefsFrom
) {
    /** Whether the address holds anything Ghidra knows about. */
    public boolean isEmpty() {
        return symbol == null && function == null && data == null && instruction == null;
    }
}
