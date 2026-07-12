// Ghidra postScript: export every function to a C file + _index.txt
// Java variant keeps headless decomp working on Ghidra 12+, where .py scripts require PyGhidra.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class DecompExport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("output directory argument required");
        }

        File outdir = new File(args[0]);
        if (!outdir.exists() && !outdir.mkdirs()) {
            throw new IllegalStateException("failed to create output directory: " + outdir);
        }

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        List<String> idx = new ArrayList<>();

        for (Function f : fm.getFunctions(true)) {
            try {
                DecompileResults r = dec.decompileFunction(f, 60, mon);
                if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                    String name = f.getName();
                    String safe = name.replaceAll("[^A-Za-z0-9_.-]", "_");
                    try (FileWriter fh = new FileWriter(new File(outdir, safe + ".c"))) {
                        fh.write(r.getDecompiledFunction().getC());
                    }
                    idx.add(f.getEntryPoint().toString() + "\t" + name + "\t" + f.getBody().getNumAddresses());
                }
            } catch (Exception ignored) {
                // Continue exporting other functions even if one decompile fails.
            }
        }

        try (FileWriter fh = new FileWriter(new File(outdir, "_index.txt"))) {
            for (int i = 0; i < idx.size(); i++) {
                if (i > 0) {
                    fh.write("\n");
                }
                fh.write(idx.get(i));
            }
        } finally {
            dec.dispose();
        }
    }
}
