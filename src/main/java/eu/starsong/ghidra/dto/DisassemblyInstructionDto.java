package eu.starsong.ghidra.dto;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

public record DisassemblyInstructionDto(
    String address,
    String bytes,
    String mnemonic,
    String operands
) {
    /**
     * Hex digits lookup. String.format("%02X", ...) parses its format string
     * and allocates a Formatter on every call, which is ~96x slower than a
     * table lookup for the byte-at-a-time encoding below.
     */
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    public static DisassemblyInstructionDto from(Instruction instr, Program program) {
        String hex;
        try {
            byte[] raw = new byte[instr.getLength()];
            program.getMemory().getBytes(instr.getAddress(), raw);
            StringBuilder sb = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                int v = b & 0xFF;
                sb.append(HEX_DIGITS[v >>> 4]).append(HEX_DIGITS[v & 0x0F]);
            }
            hex = sb.toString();
        } catch (Exception e) {
            hex = "";
        }
        String mnemonic = instr.getMnemonicString();
        StringBuilder ops = new StringBuilder();
        int n = instr.getNumOperands();
        for (int i = 0; i < n; i++) {
            if (i > 0) ops.append(", ");
            ops.append(instr.getDefaultOperandRepresentation(i));
        }
        String operands = ops.toString();
        return new DisassemblyInstructionDto(
            instr.getAddress().toString(), hex, mnemonic, operands);
    }
}
