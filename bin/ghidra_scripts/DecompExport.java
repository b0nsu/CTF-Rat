// Ghidra headless post-script: export every decompiled function and an index.
// Java keeps this compatible with Ghidra 12+, where .py scripts require PyGhidra.
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompExport extends GhidraScript {
    private static String safeName(String name) {
        return name.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    private static void write(File file, String content) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: DecompExport.java <output-directory>");
        }

        File output = new File(args[0]);
        if (!output.exists() && !output.mkdirs()) {
            throw new IOException("cannot create " + output);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        List<String> index = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        while (functions.hasNext()) {
            Function function = functions.next();
            try {
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (result != null && result.decompileCompleted()) {
                    String name = function.getName();
                    write(new File(output, safeName(name) + ".c"),
                        result.getDecompiledFunction().getC());
                    index.add(function.getEntryPoint() + "\t" + name + "\t" +
                        function.getBody().getNumAddresses());
                }
            } catch (Exception error) {
                printerr("decompile failed: " + function.getName() + ": " + error);
            }
        }
        decompiler.dispose();
        write(new File(output, "_index.txt"), String.join("\n", index));
    }
}
