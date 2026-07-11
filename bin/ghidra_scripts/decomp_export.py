# -*- coding: utf-8 -*-
# Ghidra postScript (Jython): export every function to a C file + _index.txt
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
outdir = getScriptArgs()[0]
if not os.path.exists(outdir): os.makedirs(outdir)
prog = getCurrentProgram()
dec = DecompInterface(); dec.openProgram(prog)
fm = prog.getFunctionManager(); mon = ConsoleTaskMonitor()
idx = []
for f in fm.getFunctions(True):
    try:
        r = dec.decompileFunction(f, 60, mon)
        if r and r.decompileCompleted():
            c = r.getDecompiledFunction().getC()
            name = f.getName()
            safe = "".join(ch if (ch.isalnum() or ch in "_.-") else "_" for ch in name)
            fh = open(os.path.join(outdir, safe + ".c"), "w"); fh.write(c); fh.close()
            idx.append("%s\t%s\t%d" % (f.getEntryPoint(), name, f.getBody().getNumAddresses()))
    except:
        pass
fh = open(os.path.join(outdir, "_index.txt"), "w"); fh.write("\n".join(idx)); fh.close()
