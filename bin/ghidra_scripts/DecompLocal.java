// Experimental one-function decompile after -noanalysis import.
// The result is deliberately partial: no whole-program CFG/callgraph exists.
import java.io.File;
import java.io.FileWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompLocal extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("usage: DecompLocal.java <outdir> <angr-address-hex> <pie|native>");
        }
        File output = new File(args[0]);
        if (!output.exists() && !output.mkdirs()) throw new IllegalStateException("cannot create output");
        long requested = Long.parseUnsignedLong(args[1].replaceFirst("^0[xX]", ""), 16);
        long target = requested;
        if (args[2].equals("pie")) {
            if (requested < 0x400000L) throw new IllegalArgumentException("PIE angr address below 0x400000");
            target = requested - 0x400000L + currentProgram.getImageBase().getOffset();
        } else if (!args[2].equals("native")) {
            throw new IllegalArgumentException("mapping must be pie or native");
        }
        Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
        if (address == null) throw new IllegalArgumentException("target not mapped");
        Function function = getFunctionContaining(address);
        if (function == null) {
            disassemble(address);
            function = createFunction(address, "FUN_" + Long.toHexString(target));
        }
        if (function == null) throw new IllegalStateException("function creation failed at " + address);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            DecompileResults result = decompiler.decompileFunction(function, 60, new ConsoleTaskMonitor());
            if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IllegalStateException("one-function decompile failed: " +
                    (result == null ? "no result" : result.getErrorMessage()));
            }
            try (FileWriter writer = new FileWriter(new File(output, "function.c"))) {
                writer.write(result.getDecompiledFunction().getC());
            }
            try (FileWriter writer = new FileWriter(new File(output, "scope.txt"))) {
                writer.write("address=" + address + "\nname=" + function.getName() +
                    "\nsize=" + function.getBody().getNumAddresses() + "\n");
            }
        } finally {
            decompiler.dispose();
        }
    }
}
