#!/usr/bin/env python3
"""Unified Ghidra analyzeHeadless wrapper.

Wraps Ghidra headless Java scripts into a single Python interface. Finds
analyzeHeadless, manages projects, runs Java post-scripts, returns JSON.
Usage:
  python ghidra_headless.py summary <binary>
  python ghidra_headless.py functions <binary> [limit=100]
  python ghidra_headless.py decompile <binary> <address>
  python ghidra_headless.py strings <binary> <query> [limit=100]
  python ghidra_headless.py xrefs_to <binary> <address>
  python ghidra_headless.py xrefs_from <binary> <address>
  python ghidra_headless.py functions_calling <binary> <name> [limit=100]
  python ghidra_headless.py functions_referencing_string <binary> <query> [limit=100]
  python ghidra_headless.py delete_project <project_name>
  python ghidra_headless.py list_projects
"""
import glob, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent / "ghidra" / "scripts"
PROJECTS_DIR = Path(os.environ.get("GHIDRA_PROJECTS", str(Path.home() / ".ghidra-projects"))).expanduser()
GHIDRA_HOME = Path(os.environ.get("GHIDRA_HOME", "")).expanduser()
TIMEOUT = int(os.environ.get("GHIDRA_TIMEOUT", "300"))

SCRIPTS = {
    "summary": "summary.java",
    "functions": "functions.java",
    "decompile": "decompile.java",
    "strings": "strings.java",
    "xrefs_to": "xrefs_to.java",
    "xrefs_from": "xrefs_from.java",
    "functions_calling": "finders.java",
    "functions_referencing_string": "finders.java",
}

def log(msg):
    if isinstance(msg,list): msg = " ".join(str(x) for x in msg)
    print("[ghidra] " + str(msg), file=sys.stderr, flush=True)

def find_analyze_headless():
    h = str(GHIDRA_HOME)
    if os.path.isfile(h) and h.endswith((".bat",".cmd")):
        return ["cmd.exe","/c",h]
    if os.path.isfile(h) and h.endswith(".exe"):
        return [h]
    if GHIDRA_HOME.exists():
        for ext in ["",".bat",".cmd",".exe"]:
            p = str(GHIDRA_HOME / "support" / "analyzeHeadless") + ext
            if os.path.isfile(p):
                return ["cmd.exe","/c",p] if ext in (".bat",".cmd") else [p]
    for root in ["/opt/homebrew/Cellar/ghidra", "/usr/local/Cellar/ghidra",
                 "/opt/ghidra", "/usr/share/ghidra", "C:\\tools\\ghidra",
                 os.path.expanduser("~\\tools\\ghidra")]:
        pat = os.path.join(root, "**", "support", "analyzeHeadless*")
        for f in glob.glob(pat, recursive=True):
            if os.path.isfile(f): return f
    raise FileNotFoundError("analyzeHeadless not found. Set GHIDRA_HOME or GHIDRA_PROJECTS.")

def project_name(binary_path):
    path = Path(binary_path).expanduser().resolve()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:10]
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name).strip("._")
    return f"{safe}_{digest}"

def run_headless(cmd, project):
    s = isinstance(cmd,list) and cmd and "cmd.exe" in cmd[0]
    try:
        r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT, shell=s)
        if r.returncode != 0:
            return {"error": r.stderr.strip() or r.stdout.strip(), "_project": project}
        return r
    except subprocess.TimeoutExpired:
        return {"error": f"timeout after {TIMEOUT}s", "_project": project}

def ghidra(command, binary_path, *args):
    analyze = find_analyze_headless()
    binary = Path(binary_path).expanduser().resolve()
    out_dir = Path(tempfile.mkdtemp(prefix="ghidra-out-"))
    out = out_dir / "out.json"
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    proj = project_name(binary)
    log(f"tool={command} binary={binary} project={proj}")

    exists = (PROJECTS_DIR / f"{proj}.gpr").exists()
    target = ["-process", binary.name] if exists else ["-import", str(binary)]
    script = SCRIPT_DIR / SCRIPTS[command]
    j_args = []
    if command == "functions": j_args = [str(out), str(args[0] if args else 100)]
    elif command == "strings": j_args = [str(out), str(args[0] if args else ""), str(args[1] if len(args)>1 else 100)]
    elif command in ("decompile", "xrefs_to", "xrefs_from"): j_args = [str(out), str(args[0])]
    elif command in ("functions_calling",):
        j_args = [str(out), "calling", str(args[0]), str(args[1] if len(args)>1 else 100)]
    elif command == "functions_referencing_string":
        j_args = [str(out), "string_refs", str(args[0]), str(args[1] if len(args)>1 else 100)]
    else: j_args = [str(out)]

    cmd = (analyze if isinstance(analyze,list) else [analyze]) + [str(PROJECTS_DIR), proj] + target + ["-scriptPath", str(SCRIPT_DIR), "-postScript", str(script)] + j_args
    log(cmd)
    r = run_headless(cmd, proj)
    if isinstance(r, dict):
        # retry with -import on failure
        log("retrying with -import")
        for f in [PROJECTS_DIR/f"{proj}.gpr", PROJECTS_DIR/f"{proj}.rep", PROJECTS_DIR/f"{proj}.lock"]:
            if f.exists(): f.unlink()
        cmd[len(analyze) if isinstance(analyze,list) else 3] = "-import"
        cmd[len(analyze)+1 if isinstance(analyze,list) else 4] = str(binary)
        r = run_headless(cmd, proj)
        if isinstance(r, dict): return r
    if not out.exists():
        return {"error": "no output from Ghidra script", "_project": proj}
    result = json.loads(out.read_text())
    result["_project"] = proj
    shutil.rmtree(out_dir, ignore_errors=True)
    return result

def list_projects():
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    projects = sorted(set(p.stem for p in PROJECTS_DIR.glob("*.gpr")))
    return {"projects": projects, "dir": str(PROJECTS_DIR)}

def delete_project(proj):
    for f in [PROJECTS_DIR/f"{proj}.gpr", PROJECTS_DIR/f"{proj}.rep",
              PROJECTS_DIR/f"{proj}.lock", PROJECTS_DIR/f"{proj}.lock~"]:
        if f.is_dir(): shutil.rmtree(f, ignore_errors=True)
        elif f.exists(): f.unlink()
    return {"deleted": proj, "dir": str(PROJECTS_DIR)}

def main():
    if len(sys.argv) < 2: print(json.dumps({"error": "usage: ghidra_headless.py <command> [args...]"}, indent=2)); return
    cmd = sys.argv[1]
    if cmd == "list_projects": print(json.dumps(list_projects(), indent=2)); return
    if cmd == "delete_project":
        if len(sys.argv) < 3: print(json.dumps({"error": "need project name"}, indent=2)); return
        print(json.dumps(delete_project(sys.argv[2]), indent=2)); return
    if len(sys.argv) < 3: print(json.dumps({"error": "need binary path"}, indent=2)); return
    binary = sys.argv[2]
    if cmd in SCRIPTS: print(json.dumps(ghidra(cmd, binary, *sys.argv[3:]), indent=2)); return
    print(json.dumps({"error": f"unknown command: {cmd}. Available: {list(SCRIPTS.keys())} + list_projects + delete_project"}, indent=2))
if __name__ == "__main__": main()
