# Skills Scripts

Structured Python tools for binary reverse engineering. All scripts output JSON to stdout, exit non-zero on error. Designed to be called by AI assistants (Codex) or directly from the command line.

## Directory Structure

```
skills/scripts/
├── triage.py                # Binary format identification
├── strings_scan.py          # String extraction & categorization
├── ghidra_headless.py       # Unified Ghidra analyzeHeadless wrapper (core)
├── ghidra_decompile.py      # Jython post-script for Ghidra decompilation
├── symexec_find.py          # angr symbolic execution
├── capstone_disasm.py       # Raw blob disassembly via Capstone
└── hex2bin.py               # Intel-HEX → flat binary converter
```

---

## triage.py

Identify format, architecture, endianness, entropy, and packing for any binary artifact. **Always run this first.**

```bash
python triage.py <file>
```

**Output fields:**

| Field | Description |
|-------|-------------|
| `path` | Absolute path |
| `size` | File size in bytes |
| `format` | `elf` / `pe` / `macho` / `apk` / `dex` / `ihex` / `object` / `rawfw` / `unknown` |
| `entropy` | Shannon entropy (0–8), ≥7.2 suggests packing |
| `packing` | Detected packers (UPX, high-entropy) |
| `bits` | 32 or 64 (ELF/PE only) |
| `endian` | `little` / `big` (ELF only) |
| `arch` | `x86` / `x86_64` / `arm` / `aarch64` / `mips` / `ppc` / `riscv` |
| `recommended_plan` | Suggested analysis workflow |

**Example:**

```json
{
  "path": "/tmp/sample.exe",
  "size": 153600,
  "format": "pe",
  "entropy": 6.2,
  "packing": [],
  "arch": "x86_64",
  "bits": 64,
  "pe_kind": "exe",
  "recommended_plan": "PE: IAT->strings->decompile entry"
}
```

---

## strings_scan.py

Extract and categorize ASCII + UTF-16LE strings from a binary. Categories include URLs, crypto constants, and suspicious tokens.

```bash
python strings_scan.py <file> [min_len=5]
```

**Output fields:**

| Field | Description |
|-------|-------------|
| `path` | Absolute path |
| `total` | Total strings found |
| `categories.urls` | URL-like strings |
| `categories.crypto` | Crypto-related tokens (AES, SHA, HMAC, ...) |
| `categories.suspicious` | Suspicious tokens (password, api_key, backdoor, ...) |

**Example:**

```json
{
  "path": "/tmp/sample.exe",
  "total": 423,
  "categories": {
    "urls": ["https://api.example.com/v2/login"],
    "crypto": ["AES", "SHA-256", "RC4"],
    "suspicious": ["password", "IsDebuggerPresent"]
  }
}
```

---

## ghidra_headless.py *(core)*

Unified wrapper around Ghidra's `analyzeHeadless`. Auto-discovers Ghidra installation, manages projects, runs Java post-scripts, returns JSON.

```bash
python ghidra_headless.py <command> <binary> [args...]
```

**Commands:**

| Command | Args | Description |
|---------|------|-------------|
| `summary` | `<binary>` | Binary overview (name, language, image base, function count) |
| `functions` | `<binary> [limit=100]` | List functions by address and name |
| `decompile` | `<binary> <address>` | Decompile function at address to pseudo-C |
| `strings` | `<binary> <query> [limit=100]` | Find strings containing query (case-insensitive) |
| `xrefs_to` | `<binary> <address>` | Cross-references TO an address |
| `xrefs_from` | `<binary> <address>` | Cross-references FROM an address |
| `functions_calling` | `<binary> <name> [limit=100]` | Functions that call a symbol (by name substring) |
| `functions_referencing_string` | `<binary> <query> [limit=100]` | Functions that reference a string |
| `list_projects` | (none) | List all Ghidra projects |
| `delete_project` | `<project_name>` | Delete a project |

**Environment variables:**

- `GHIDRA_HOME` — Ghidra installation root (required)
- `GHIDRA_PROJECTS` — project storage directory (default: `~/.ghidra-projects`)
- `GHIDRA_TIMEOUT` — headless timeout in seconds (default: `300`)

**Caching:** Each binary gets a deterministic project name derived from its SHA-256, so subsequent runs reuse the analyzed project.

**Fallback:** On failure, retries with `-import` flag (clears stale project first).

---

## ghidra_decompile.py

Jython (Python 2) post-script for Ghidra headless decompilation. Called internally by `ghidra_headless.py` — not typically invoked directly.

```bash
# Via analyzeHeadless directly:
analyzeHeadless <projDir> <proj> -import <file> \
  -scriptPath ghidra/scripts \
  -postScript ghidra_decompile.py <mode> [arg]
```

**Modes:**

| Mode | Arg | Description |
|------|-----|-------------|
| `list` | — | List all functions |
| `func` | `<name\|0xADDR>` | Decompile a single function |
| `all` | `[maxFuncs=40]` | Decompile top-N largest functions |

---

## symexec_find.py

angr symbolic execution to find stdin/argv inputs that reach a target address. Useful for solving license checks, password validators, and crackmes. **Static analysis only — does not execute the binary.**

```bash
python symexec_find.py <binary> --find 0xADDR[,0xADDR2] \
  [--stdin N] [--arg N] [--avoid 0xADDR3] [--base 0x0] [--timeout 120]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--find 0xADDR` | Target address(es) to reach (comma-separated) |
| `--stdin N` | Symbolic stdin of N bytes |
| `--arg N` | Symbolic argv[1] of N bytes |
| `--avoid 0xADDR` | Addresses to avoid |
| `--base 0x0` | Load base address |
| `--timeout 120` | Timeout in seconds |

**Requires:** `pip install angr claripy`

**Example output:**

```json
{
  "result": "solved",
  "reached": ["0x401200"],
  "input_hex": "6b6579313233",
  "input_channel": "stdin",
  "input_ascii": "key123"
}
```

---

## capstone_disasm.py

Linear disassembly of raw binary blobs or firmware images via [Capstone](http://www.capstone-engine.org/).

```bash
python capstone_disasm.py <file> --arch <arch> [--base 0x0] [--count 256] [--thumb]
```

**Supported architectures:** `x86`, `x86_64`, `arm`, `armthumb`, `aarch64`, `mips`

**Options:**

| Option | Description |
|--------|-------------|
| `--arch <arch>` |