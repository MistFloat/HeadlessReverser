#!/usr/bin/env python3
"""Identify a black-box artifact: format, arch, endianness, entropy/packing, plan."""
import json, math, os, struct, sys

def shannon_entropy(data):
    if not data: return 0.0
    counts=[0]*256
    for b in data: counts[b]+=1
    n=len(data); e=0.0
    for c in counts:
        if c: p=c/n; e-=p*math.log2(p)
    return round(e,3)

def detect_format(head,path):
    n=path.lower()
    if head[:4]==b"\x7fELF": return "elf"
    if head[:2]==b"MZ": return "pe"
    if head[:4] in (b"\xfe\xed\xfa\xce",b"\xfe\xed\xfa\xcf",b"\xce\xfa\xed\xfe",b"\xcf\xfa\xed\xfe"): return "macho"
    if head[:4]==b"PK\x03\x04":
        if n.endswith(".apk"): return "apk"
        if n.endswith(".jar"): return "jar"
        return "zip"
    if head[:4]==b"dex\n": return "dex"
    if head[:1]==b":" and all(c in b"0123456789ABCDEFabcdef:\r\n" for c in head[:32]): return "ihex"
    if n.endswith((".hex",)): return "ihex"
    if n.endswith((".o",".obj")): return "object"
    if n.endswith((".bin",".img",".rom",".fw")): return "rawfw"
    return "unknown"

EM={0x03:"x86",0x3E:"x86_64",0x28:"arm",0xB7:"aarch64",0x08:"mips",0x14:"ppc",0xF3:"riscv"}
PM={0x14C:"x86",0x8664:"x86_64",0x1C0:"arm",0xAA64:"aarch64",0x1C4:"armv7"}

EN2={1:"little",2:"big"}; ET={1:"relocatable(.o)",2:"executable",3:"shared-object/PIE",4:"core"}
def main():
    if len(sys.argv)<2: return 2
    path=sys.argv[1]
    if not os.path.isfile(path): return 2
    sz=os.path.getsize(path)
    with open(path,"rb") as f:
        h=f.read(65536); f.seek(max(0,sz-65536)); t=f.read(65536)
    s=h+t; fmt=detect_format(h,path)
    ent=shannon_entropy(s)
    out={"path":os.path.abspath(path),"size":sz,"format":fmt,"entropy":ent,"packing":[]}
    if b"UPX!" in s[:4096]: out["packing"].append("UPX")
    if ent>=7.2: out["packing"].append("high-entropy")
    if fmt in("elf","object") and len(h)>=20:
        out["bits"]=64 if h[4]==2 else 32
        out["endian"]=EN2.get(h[5],"?")
        out["arch"]=EM.get(struct.unpack_from("<H",h,18)[0],"?")
        out["elf_type"]=ET.get(struct.unpack_from("<H",h,16)[0],"?")
    elif fmt=="pe":
        e=struct.unpack_from("<I",h,0x3C)[0]
        if data[e:e+4]==b"PE\x00\x00":
            m=struct.unpack_from("<H",h,e+4)[0]
            out["arch"]=PM.get(m,"0x%x"%m)
            out["pe_kind"]="dll" if struct.unpack_from("<H",h,e+22)[0]&0x2000 else "exe"
            out["bits"]=32 if m==0x14C else 64
    out["recommended_plan"]={"elf":"ELF: symbols->strings->disasm/decompile","pe":"PE: IAT->strings->decompile entry",
        "macho":"Mach-O: symbols/load-cmds->decompile","apk":"APK: apktool+jadx->trace",
        "ihex":"HEX: hex2bin->capstone disasm","unknown":"file+hex+strings"}.get(fmt,"triage->analyze")
    print(json.dumps(out,indent=2))
if __name__=="__main__": main()
