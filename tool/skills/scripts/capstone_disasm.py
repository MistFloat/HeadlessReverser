#!/usr/bin/env python3
# Linear disassembly of raw blob/firmware via capstone.
import json, os, sys
def main():
    a = {"base": 0, "offset": 0, "count": 256, "arch": None, "thumb": False, "file": None}
    i = 1
    while i < len(sys.argv):
        t = sys.argv[i]
        if t == "--arch": i += 1; a["arch"] = sys.argv[i]
        elif t == "--base": i += 1; a["base"] = int(sys.argv[i], 0)
        elif t == "--count": i += 1; a["count"] = int(sys.argv[i], 0)
        elif t == "--thumb": a["thumb"] = True
        elif not t.startswith("-") and a["file"] is None: a["file"] = t
        i += 1
    if not a["file"] or not os.path.isfile(a["file"]) or not a["arch"]:
        print(json.dumps({"error": "usage: capstone_disasm.py <file> --arch <arch> [--base 0x0] [--count N]"})); return 2
    try:
        import capstone as cs
        M = {"x86": (cs.CS_ARCH_X86, cs.CS_MODE_32), "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
             "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM), "armthumb": (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB),
             "aarch64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
             "mips": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_LITTLE_ENDIAN)}
        k = "armthumb" if (a["arch"] == "arm" and a["thumb"]) else a["arch"]
        if k not in M: raise ValueError("unsupported arch: " + a["arch"])
        md = cs.Cs(*M[k]); md.detail = False
    except Exception as e: print(json.dumps({"error": str(e)})); return 2
    with open(a["file"], "rb") as f: f.seek(a["offset"]); blob = f.read()
    addr = a["base"] + a["offset"]; lines = []
    for ins in md.disasm(blob, addr):
        lines.append("0x%08x:  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
        if len(lines) >= a["count"]: break
    print(json.dumps({"file": os.path.abspath(a["file"]), "arch": a["arch"], "instructions": len(lines)}, indent=2))
    print("\n".join(lines))
if __name__ == "__main__": main()
