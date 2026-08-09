// Ghidra headless post-script: create/decompile one function at a requested
// address and add it to the existing decomp cache.
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompOne extends GhidraScript {
    private static String safeName(String name) {
        return name.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    private static String funName(long value) {
        return String.format("FUN_%08x", value);
    }

    private static long parseAddrArg(String text) {
        String s = text.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            s = s.substring(2);
        }
        return Long.parseUnsignedLong(s, 16);
    }

    private static void write(File file, String content) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }

    private static void upsertIndex(File indexFile, String line, String addrText) throws IOException {
        List<String> lines = new ArrayList<>();
        if (indexFile.exists()) {
            for (String old : Files.readAllLines(indexFile.toPath())) {
                if (!old.startsWith(addrText + "\t")) {
                    lines.add(old);
                }
            }
        }
        lines.add(line);
        write(indexFile, String.join("\n", lines) + "\n");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: DecompOne.java <output-directory> <address-hex>");
        }

        File output = new File(args[0]);
        if (!output.exists() && !output.mkdirs()) {
            throw new IOException("cannot create " + output);
        }

        long value = parseAddrArg(args[1]);
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
        if (addr == null) {
            throw new IllegalArgumentException("bad address: " + args[1]);
        }

        // A requested address can be an interior basic block.  Reusing its
        // containing function preserves Ghidra's analysis instead of creating
        // a false entry point in the middle of an instruction stream.
        Function function = getFunctionContaining(addr);
        if (function == null) {
            clearListing(addr, addr.add(0x80));
            disassemble(addr);
            function = createFunction(addr, funName(value));
        }
        if (function == null) {
            clearListing(addr, addr.add(0x200));
            disassemble(addr);
            function = createFunction(addr, funName(value));
        }
        if (function == null) {
            throw new IllegalStateException("cannot create or find function at " + addr);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        try {
            DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
            if (result == null || !result.decompileCompleted()) {
                String err = result == null ? "no result" : result.getErrorMessage();
                throw new IllegalStateException("decompile failed: " + err);
            }
            String name = function.getName();
            write(new File(output, safeName(name) + ".c"),
                result.getDecompiledFunction().getC());
            upsertIndex(new File(output, "_index.txt"),
                function.getEntryPoint() + "\t" + name + "\t" + function.getBody().getNumAddresses(),
                function.getEntryPoint().toString());
        } finally {
            decompiler.dispose();
        }
    }
}
