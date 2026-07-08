#!/usr/bin/env python3
# Extract and categorize strings from a binary. JSON output.
import json, os, re, sys
MINLEN = 5
P = {
    "urls": re.compile(r'\b(?:https?|ftp|wss?)://[^\s"<>\']{4,}'),
    "crypto": re.compile(r'\b(?:AES|DES|RC4|RSA|SHA-?1|SHA-?256|SHA-?512|MD5|HMAC|XOR|ChaCha20|Blowfish|CRC)\b', re.I),
    "suspicious": re.compile(r'\b(?:password|secret|api[_-]?key|token|license|backdoor|ptrace|IsDebuggerPresent|VirtualAlloc)\b', re.I),
}
def extract(data, ml):
    out = []; cur = bytearray()
    for b in data:
        if 0x20 <= b < 0x7F: cur.append(b)
        else:
            if len(cur) >= ml: out.append(cur.decode("ascii", "ignore"))
            cur = bytearray()
    if len(cur) >= ml: out.append(cur.decode("ascii", "ignore"))
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){%d,}' % ml, data):
        out.append(m.group().decode("utf-16le", "ignore"))
    return out
def main():
    if len(sys.argv) < 2: return 2
    path = sys.argv[1]; ml = int(sys.argv[2]) if len(sys.argv) > 2 else MINLEN
    if not os.path.isfile(path): return 2
    with open(path, "rb") as f: data = f.read()
    strs = extract(data, ml)
    buckets = {k: [] for k in P}; seen = {k: set() for k in P}
    for s in strs:
        for k, rx in P.items():
            if rx.search(s) and s.strip() not in seen[k]:
                seen[k].add(s.strip()); buckets[k].append(s.strip())
    buckets = {k: v[:60] for k, v in buckets.items() if v}
    print(json.dumps({"path": os.path.abspath(path), "total": len(strs), "categories": buckets}, indent=2))
if __name__ == "__main__": main()
