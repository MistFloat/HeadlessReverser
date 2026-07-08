#!/usr/bin/env python3
# Intel-HEX (.hex) to flat binary + layout report. JSON output.
import json, os, sys
def main():
    path = None; out = None
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == "-o": i += 1; out = sys.argv[i]
        elif path is None: path = a
        i += 1
    if not path or not os.path.isfile(path):
        print(json.dumps({"error": "usage: hex2bin.py <file.hex> [-o out.bin] [--pad 0xFF]"})); return 2
    if out is None: out = os.path.splitext(path)[0] + ".bin"
    try:
        from intelhex import IntelHex
        ih = IntelHex(path); ih.tofile(out, "bin")
        info = {"base": hex(ih.minaddr()), "end": hex(ih.maxaddr()), "size": ih.maxaddr() - ih.minaddr() + 1, "parser": "intelhex"}
    except:
        mem = {}; base_addr = 0
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line.startswith(":"): continue
                raw = bytes.fromhex(line[1:])
                cnt, addr, typ = raw[0], (raw[1] << 8) | raw[2], raw[3]
                data = raw[4:4+cnt]
                if typ == 0:
                    for j, b in enumerate(data): mem[base_addr + addr + j] = b
                elif typ == 1: break
                elif typ == 2: base_addr = ((data[0] << 8) | data[1]) << 4
                elif typ == 4: base_addr = ((data[0] << 8) | data[1]) << 16
        if not mem: print(json.dumps({"error": "no data records parsed"})); return 2
        mina, maxa = min(mem), max(mem)
        buf = bytearray([0xFF]) * (maxa - mina + 1)
        for a, b in mem.items(): buf[a - mina] = b
        with open(out, "wb") as f: f.write(buf)
        info = {"base": hex(mina), "end": hex(maxa), "size": maxa - mina + 1, "parser": "builtin"}
    info["output"] = os.path.abspath(out)
    print(json.dumps(info, indent=2))
if __name__ == "__main__": main()
