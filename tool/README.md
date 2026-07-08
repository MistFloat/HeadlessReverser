# reverse-skill Fusion

> Fusion layer for AI-assisted binary reverse engineering — methodology + tool orchestration + Ghidra headless scripting.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-11.x-orange.svg)](https://ghidra-sre.org/)

A unified toolset that wraps [Ghidra](https://ghidra-sre.org/) `analyzeHeadless` into a structured Python interface, designed for AI coding assistants (Codex, Copilot, etc.) to perform automated binary reverse engineering tasks. Fuses:

- **Methodology depth** from [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (21 installed Codex skills)
- **Tool orchestration** from [maosasagawa/blackbox-re-agent](https://github.com/maosasagawa/blackbox-re-agent) (adaptive backends, structured tools, angr symbolic execution)
- **Ghidra headless scripting** from [Hyeongrok1/codex-mcp-ghidra](https://github.com/Hyeongrok1/codex-mcp-ghidra) (7 Java post-scripts)

## Architecture

```
reverse-skill/
├── CODEX.md                     # Codex entry point + logic report template
├── skills/scripts/              # Python orchestration tools
│   ├── ghidra_headless.py       # ★ Core: Unified Ghidra analyzeHeadless wrapper
│   ├── triage.py                # Binary format/arch/packing identification
│   ├── strings_scan.py          # String extraction & categorization
│   ├── symexec_find.py          # angr symbolic execution (license/password solving)
│   ├── capstone_disasm.py       # Raw blob disassembly via Capstone
│   ├── hex2bin.py               # Intel-HEX → flat binary converter
│   └── ghidra_decompile.py     # Jython post-script for Ghidra decompilation
└── ghidra/scripts/              # Ghidra headless Java post-scripts
    ├── summary.java             # Binary overview
    ├── functions.java           # Function listing
    ├── decompile.java           # Pseudo-C decompilation
    ├── strings.java             # String search
    ├── xrefs_to.java            # Cross-references TO address
    ├── xrefs_from.java          # Cross-references FROM address
    └── finders.java             # Function search (callers / string references)
```

## Quick Start

### Prerequisites

- **Python 3.8+**
- **Ghidra 11.x** — set `GHIDRA_HOME` environment variable
- **JDK 17+** (required by Ghidra)

### Setup

```bash
# Clone
git clone https://github.com/<your-org>/reverse-skill.git
cd reverse-skill

# Set environment variables
export GHIDRA_HOME=/path/to/ghidra_11.x
export GHIDRA_PROJECTS=~/.ghidra-projects   # default
export GHIDRA_TIMEOUT=300                    # default, in seconds

# Optional: install extra backends
pip install angr claripy     # for symexec_find.py
pip install capstone         # for capstone_disasm.py
pip install intelhex         # for hex2bin.py (uses built-in fallback otherwise)
```

### Usage

```bash
# 1. Identify the binary
python skills/scripts/triage.py sample.exe

# 2. Extract strings
python skills/scripts/strings_scan.py sample.exe

# 3. Ghidra analysis (requires GHIDRA_HOME)
python skills/scripts/ghidra_headless.py summary sample.exe
python skills/scripts/ghidra_headless.py functions sample.exe 50
python skills/scripts/ghidra_headless.py decompile sample.exe 0x401000
python skills/scripts/ghidra_headless.py strings sample.exe "http" 20
python skills/scripts/ghidra_headless.py xrefs_to sample.exe 0x401000
python skills/scripts/ghidra_headless.py xrefs_from sample.exe 0x401000
python skills/scripts/ghidra_headless.py functions_calling sample.exe "strcmp"
python skills/scripts/ghidra_headless.py functions_referencing_string sample.exe "password"

# 4. Symbolic execution (optional)
python skills/scripts/symexec_find.py sample.exe --find 0x401200 --stdin 32

# 5. Raw firmware / blob disassembly
python skills/scripts/capstone_disasm.py firmware.bin --arch arm --base 0x8000000

# 6. Convert Intel HEX
python skills/scripts/hex2bin.py firmware.hex -o firmware.bin

# 7. Manage Ghidra projects
python skills/scripts/ghidra_headless.py list_projects
python skills/scripts/ghidra_headless.py delete_project my_project
```

## Tools Reference

| Script | Function | Output | Dependencies |
|--------|----------|--------|-------------|
| `triage.py` | Identify format, arch, endianness, packing | JSON | Python stdlib |
| `strings_scan.py` | Extract & categorize strings (URLs, crypto, suspicious) | JSON | Python stdlib |
| `ghidra_headless.py` | Unified Ghidra analyzeHeadless wrapper (9 commands) | JSON | Ghidra + JDK 17+ |
| `symexec_find.py` | angr symbolic execution for license/password checks | JSON | `angr`, `claripy` |
| `capstone_disasm.py` | Linear disassembly of raw blobs/firmware | JSON + text | `capstone` |
| `hex2bin.py` | Intel-HEX → flat binary + layout report | JSON | `intelhex` (optional) |
| `ghidra_decompile.py` | Jython post-script (called internally by ghidra_headless.py) | Text | Ghidra |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_HOME` | (required) | Ghidra installation root directory |
| `GHIDRA_PROJECTS` | `~/.ghidra-projects` | Ghidra project storage directory |
| `GHIDRA_TIMEOUT` | `300` | Ghidra headless timeout in seconds |

## How Ghidra Headless Works

`ghidra_headless.py` is the core orchestration layer. It:

1. Auto-discovers `analyzeHeadless` from `GHIDRA_HOME` or common install paths
2. Creates/opens a Ghidra project for each binary (deterministic name via SHA-256)
3. Invokes the appropriate Java post-script from `ghidra/scripts/`
4. Captures the JSON output and returns it
5. Cleans up temporary files

The project-per-binary approach means the first run imports (slow), subsequent runs use the cached project (fast).

## Adaptive Backend Selection

Each analysis operation prefers the best available backend and degrades gracefully:

| Goal | 1st Choice | Fallback |
|------|-----------|----------|
| Format ID | `triage.py` | — |
| Disassembly | Ghidra | rizin/r2 → objdump → `capstone_disasm.py` |
| Decompilation | Ghidra headless | rizin `pdg` → rizin `pdc` |
| Strings | `strings_scan.py` | — |
| Symbolic exec | `symexec_find.py` (angr) | — |

## Using with Codex / AI Assistants

Load `CODEX.md` as the system prompt or skill entry point. It contains:

- Full architecture overview
- Core principles (adaptive backend, graceful degradation, evidence-linked reporting)
- Logic Report template
- Task completion checklist

## Contributing

Issues and PRs welcome. The Java scripts in `ghidra/scripts/` must be compatible with Ghidra 11.x API.

## License

This fusion layer: **MIT** ([LICENSE](LICENSE))

Upstream projects:
- [reverse-skill](https://github.com/zhaoxuya520/reverse-skill): MIT
- [blackbox-re-agent](https://github.com/maosasagawa/blackbox-re-agent): Apache 2.0
- [codex-mcp-ghidra](https://github.com/Hyeongrok1/codex-mcp-ghidra): no license
