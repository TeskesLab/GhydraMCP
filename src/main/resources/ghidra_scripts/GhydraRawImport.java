// Verify native raw-loader mapping before analysis and API startup.
// @category GhydraMCP

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;

public class GhydraRawImport extends HeadlessScript {
    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        String[] args = getScriptArgs();
        try {
            if (!isImporting() || currentProgram == null || args.length != 1
                    || !args[0].matches("0x[0-9a-f]+")) {
                throw new IllegalArgumentException("One canonical raw load address is required.");
            }
            AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
            BigInteger requested = new BigInteger(args[0].substring(2), 16);
            BigInteger maximum = new BigInteger(Long.toUnsignedString(
                space.getMaxAddress().getAddressableWordOffset()));
            if (requested.compareTo(maximum) > 0) {
                throw new IllegalArgumentException("Raw load address exceeds the native address space.");
            }
            // The native string parser uses addressable words, not byte offsets.
            Address expected = space.getAddress(args[0]);
            Path input = new java.io.File(currentProgram.getExecutablePath()).toPath();
            if (!input.isAbsolute()) {
                throw new IllegalArgumentException("Raw input must have an absolute source path.");
            }
            long inputSize = Files.size(input);
            boolean mapped = false;
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                if (!block.getStart().equals(expected)) continue;
                for (var source : block.getSourceInfos()) {
                    var fileBytes = source.getFileBytes();
                    if (fileBytes.isPresent() && source.getFileBytesOffset() == 0
                            && fileBytes.get().getSize() == inputSize
                            && source.getLength() == inputSize && block.getSize() == inputSize) {
                        mapped = true;
                        break;
                    }
                }
            }
            if (!mapped) {
                throw new IllegalArgumentException("Raw input was not mapped at the requested address.");
            }
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception failure) {
            // Return normally: throwing makes HeadlessAnalyzer replace the
            // delete disposition with ABORT, which could save a bad import.
            printerr("Raw import verification failed: " + failure.getMessage());
        }
    }
}
