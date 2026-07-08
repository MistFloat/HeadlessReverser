#!/usr/bin/env python3
# angr symbolic execution: find stdin/argv input reaching target address.
import json, sys, time
def main():
    a = {"bin": None, "find": [], "avoid": [], "stdin": None, "arg": None, "base": None, "timeout": 120}
    i = 1
    while i < len(sys.argv):
        t = sys.argv[i]
        if t == "--find": i += 1; a["find"] = [int(x, 0) for x in sys.argv[i].split(",")]
        elif t == "--avoid": i += 1; a["avoid"] = [int(x, 0) for x in sys.argv[i].split(",") if x]
        elif t == "--stdin": i += 1; a["stdin"] = int(sys.argv[i])
        elif t == "--arg": i += 1; a["arg"] = int(sys.argv[i])
        elif t == "--base": i += 1; a["base"] = int(sys.argv[i], 0)
        elif t == "--timeout": i += 1; a["timeout"] = int(sys.argv[i])
        elif not t.startswith("-") and a["bin"] is None: a["bin"] = t
        i += 1
    if not a["bin"] or not a["find"]: print(json.dumps({"error": "usage: symexec_find.py <bin> --find 0xADDR"})); return 2
    try:
        import angr, claripy
        import logging; logging.getLogger("angr").setLevel(logging.ERROR); logging.getLogger("cle").setLevel(logging.ERROR)
    except Exception as e: print(json.dumps({"error": "angr missing: " + str(e)})); return 3
    lo = {"auto_load_libs": False}
    if a["base"]: lo["main_opts"] = {"base_addr": a["base"]}
    proj = angr.Project(a["bin"], load_options=lo)
    sym = None
    if a["arg"]: sym = claripy.BVS("arg", a["arg"]*8); state = proj.factory.entry_state(args=[a["bin"], sym])
    elif a["stdin"]: sym = claripy.BVS("stdin", a["stdin"]*8); state = proj.factory.entry_state(stdin=sym)
    else: state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state); deadline = time.time() + a["timeout"]
    while simgr.active and time.time() < deadline:
        simgr.explore(find=lambda s: s.addr in a["find"], avoid=lambda s: s.addr in a["avoid"], n=1)
        if simgr.found: break
    if not simgr.found: print(json.dumps({"result": "no_solution", "active": len(simgr.active), "deadended": len(simgr.deadended)})); return 0
    s = simgr.found[0]; out = {"result": "solved", "reached": [hex(x) for x in a["find"]]}
    if sym:
        v = s.solver.eval(sym, cast_to=bytes)
        out["input_hex"] = v.hex()
        out["input_channel"] = "argv" if a["arg"] else "stdin"
        try: out["input_ascii"] = v.split(b"\x00")[0].decode("latin-1")
        except: pass
    try:
        stdout = s.posix.dumps(1)
        if stdout: out["program_stdout"] = stdout.decode("latin-1", "ignore")[:2000]
    except: pass
    print(json.dumps(out, indent=2))
if __name__ == "__main__": main()
