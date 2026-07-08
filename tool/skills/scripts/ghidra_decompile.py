# -*- coding: utf-8 -*-
# Ghidra headless post-script (Jython/Python 2) - decompile functions to pseudo-C.
# Usage via analyzeHeadless:
#   analyzeHeadless <projDir> <proj> -import <file> -scriptPath <dir> -postScript ghidra_decompile.py <mode> [arg] -deleteProject
# mode: func <name|0xADDR> | all [maxFuncs=40] | list
import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
MARK = "===REVAGENT-DECOMP==="
def decomp_iface():
    di = DecompInterface(); di.openProgram(currentProgram); return di
def decompile_one(di, func, monitor):
    res = di.decompileFunction(func, 60, monitor)
    if res and res.decompileCompleted(): return res.getDecompiledFunction().getC()
    return "// decompile failed for " + func.getName()
def main():
    a = getScriptArgs()
    mode = a[0] if len(a) > 0 else "all"
    arg = a[1] if len(a) > 1 else None
    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()
    di = decomp_iface()
    if mode == "list":
        print(MARK + "LIST")
        for f in fm.getFunctions(True):
            print("%s\t%s\t%d" % (f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses()))
        print(MARK + "END"); return
    if mode == "func" and arg:
        target = None
        if arg.startswith("0x") or arg.startswith("0X"):
            addr = currentProgram.getAddressFactory().getAddress(arg)
            target = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        else:
            for f in fm.getFunctions(True):
                if f.getName() == arg: target = f; break
        if target is None: print(MARK + "ERROR\nfunction not found: " + arg); return
        print(MARK + "FUNC %s @ %s" % (target.getName(), target.getEntryPoint()))
        print(decompile_one(di, target, monitor))
        print(MARK + "END"); return
    maxf = int(arg) if arg else 40
    funcs = list(fm.getFunctions(True))
    funcs.sort(key=lambda f: f.getBody().getNumAddresses(), reverse=True)
    funcs = funcs[:maxf]
    print(MARK + "ALL %d functions" % len(funcs))
    for f in funcs:
        if f.isThunk(): continue
        print(MARK + "FUNC %s @ %s" % (f.getName(), f.getEntryPoint()))
        print(decompile_one(di, f, monitor))
    print(MARK + "END")
main()
