# Reverse Engineering Fusion — Codex Skill System

> Fusion of `zhaoxuya520/reverse-skill` (methodology depth) +
> `maosasagawa/blackbox-re-agent` (tool orchestration) +
> `Hyeongrok1/codex-mcp-ghidra` (Ghidra headless scripting).

## How This System Works

When the user asks to analyze a binary, APK, firmware, or any compiled artifact:

1. Read this file once to understand the architecture
2. Use `skills/scripts/` Python tools for structured operations
3. Reference `~/.codex/skills/<format>/SKILL.md` for format-specific methodology
4. Produce a **Logic Report** (see template below)

## Architecture

```
User Request
  |
  v
[CODEX.md]  <-- you are here: routing + principles
  |
  +-- skills/scripts/          -- Structured tools (triage, strings, symexec, etc.)
  |     triage.py              Identify format/arch/packing (JSON output)
  |     strings_scan.py        Extract & categorize strings
  |     symexec_find.py        angr symbolic execution for input solving
  |     capstone_disasm.py     Raw blob disassembly via capstone
  |     hex2bin.py             Intel-HEX to flat binary converter
  |     ghidra_headless.py     Unified Ghidra analyzeHeadless wrapper
  |     ghidra_decompile.py    Jython post-script for Ghidra decompilation
  |
  +-- ~/.codex/skills/         -- Methodology (already installed as Codex skills)
  |     reverse-engineering/   General RE methodology + references
  |     apk-reverse/           APK workflow (jadx, apktool, Frida)
  |     ida-reverse/           IDA Pro MCP (72 tools)
  |     mobile-reverse/        Android + iOS unified
  |     radare2/               r2 analysis
  |     firmware-pentest/      Firmware/IoT analysis
  |     pwn-chain/             Stack/heap/kernel exploitation
  |     ... (21 skills total)
  |
  +-- ghidra/scripts/          -- Ghidra headless Java post-scripts
        summary.java           Binary overview
        functions.java         Function listing
        decompile.java         Pseudo-C decompilation
        strings.java           String search
        xrefs_to.java          Cross-references TO an address
        xrefs_from.java        Cross-references FROM an address
        finders.java           Function search (calling/referencing string)
```

## Core Principles

### 1. Adaptive Backend Selection

Each analysis operation has a preferred backend and fallback chain:

| Goal             | Select the first available:                                    |
|------------------|---------------------------------------------------------------|
| Format ident.    | `triage.py` (pure Python)                                     |
| Disassembly      | Ghidra/IDA Pro -> rizin/r2 -> objdump -> `capstone_disasm.py` |
| Decompilation    | Ghidra headless -> rizin `pdg` -> rizin `pdc`                 |
| Strings          | `strings_scan.py` (never guess command-line strings flags)    |
| Symbolic exec    | `symexec_find.py` (angr wrapper)                              |
| Memory/sections  | `ghidra_headless.py` sections -> PE built-in parser           |

### 2. Degrade Gracefully, Then Provision

```
1. Run `triage.py` to identify format
2. Analyze with what's installed
3. If a step is blocked by a missing tool:
   a) Say what's missing and what it would unlock
   b) Try the fallback backend from the chain above
   c) If no fallback available, run `~/.codex/skills/scripts/bootstrap-reverse.sh`
4. Continue with partial results
```

### 3. Evidence-Linked Reporting

Tie every claim to a concrete address, symbol, string, or decompiled snippet.
Never say "the function checks the password" without citing the address.

### 4. Static Analysis Only by Default

Do not execute, install, or run untrusted samples. The `symexec_find.py` tool
reasons over code paths in angr's isolated VM without running the binary.

## How to Use Ghidra (analyzeHeadless)

The `ghidra_headless.py` script wraps Ghidra's analyzeHeadless:

```bash
# Prerequisites
set GHIDRA_HOME=C:\path\to\ghidra
set GHIDRA_PROJECTS=%USERPROFILE%\.ghidra-projects

# Commands
python ghidra_headless.py summary binary.exe          # Binary overview
python ghidra_headless.py functions binary.exe 50     # List first 50 functions
python ghidra_headless.py decompile binary.exe 0x401000  # Decompile at address
python ghidra_headless.py strings binary.exe "http" 20  # Find strings matching "http"
python ghidra_headless.py xrefs_to binary.exe 0x401000   # Who references this addr
python ghidra_headless.py xrefs_from binary.exe 0x401000  # What this addr references
python ghidra_headless.py functions_calling binary.exe "strcmp"  # Functions calling strcmp
python ghidra_headless.py list_projects                   # List all projects
python ghidra_headless.py delete_project proj_name         # Delete a project
```

### Adaptive Fallback for Ghidra

If Ghidra is not available:
1. First try `rizin`/`radare2` for disassembly (`pdc`/`pdg` decompiler)
2. Then try `objdump` for basic disassembly
3. For raw blobs/firmware: `capstone_disasm.py --arch <arch>`
4. Report what's missing and offer to provision

## Workflow: Any Unknown Binary

1. python skills/scripts/triage.py <file>       # Identify format
2. python skills/scripts/strings_scan.py <file> # Extract strings
3. Load the matching skill from ~/.codex/skills/<format>/SKILL.md
4. If ELF/PE/Mach-O: use ghidra_headless.py for decompilation
5. If license/password check: symexec_find.py
6. If firmware: hex2bin.py -> capstone_disasm.py
7. Produce Logic Report

## Logic Report Template

At the end of every analysis, produce a structured report:

```markdown
# Logic Report: <file>

## 1. Identity & Format
- **File**: path
- **Format**: ELF/PE/Mach-O/APK/HEX
- **Arch**: x86_64/ARM/AArch64/MIPS
- **Bits/Endian**: 64-bit LE
- **Packing**: UPX / high-entropy (7.5) / none
- **Size**: N bytes

## 2. Entrypoints & Structure
- **Entrypoint**: 0x...
- **Sections**: .text (0x...), .rodata (0x...), .data (0x...)
- **Imports**: strcmp, fopen, connect, CCCrypt...
- **Strings**: 3 URLs, 2 crypto constants, 5 suspicious tokens

## 3. Key Functions (reconstructed logic)
| Address | Name | Purpose |
|---------|------|---------|
| 0x401000 | check_password | Compares input via strcmp at 0x401050 |
| 0x402000 | decrypt_config | XOR loop with key at 0x403000 |

### Function details (evidence-linked):
- **check_password** (0x401000): Takes user input, calls strcmp(address=0x401050, input, hardcoded="secret123"). If match -> 0x401200 (success), else -> 0x401300 (failure).

## 4. Data
- **Hardcoded strings**: "secret123" @ 0x403100, "https://api.example.com" @ 0x403200
- **Crypto constants**: AES S-box @ 0x404000, RC4 key array @ 0x404800
- **Embedded resources**: HTML template @ 0x405000 (962 bytes)

## 5. External Interactions
- **Network**: connects to api.example.com:443 (TLS), POST /v2/login
- **Files**: reads /etc/config.ini, writes /tmp/cache.bin
- **IPC**: Unix domain socket /var/run/svc.sock

## 6. Notable Findings
- [CRITICAL] Hardcoded AES key in .rodata @ 0x404100 (32 bytes)
- [HIGH] Stack buffer overflow in parse_input() @ 0x406000: memcpy(src=input, len=request_len, dst=64-byte buf)
- [MEDIUM] Debug log writes to /tmp/debug.log includes sensitive data

## 7. Open Questions
- The HMAC key's origin is unknown; may be derived at runtime
- The RPC protocol uses custom framing, need further reversal
```

## References to Installed Skills

The following skills are already installed in `~/.codex/skills/`. Load their
SKILL.md when the target matches:

| Format/Task       | Skill path                                        |
|-------------------|---------------------------------------------------|
| General RE        | `~/.codex/skills/reverse-engineering/SKILL.md`    |
| APK / Android     | `~/.codex/skills/apk-reverse/SKILL.md`            |
| IDA Pro           | `~/.codex/skills/ida-reverse/SKILL.md`            |
| Mobile (iOS+And)  | `~/.codex/skills/mobile-reverse/SKILL.md`         |
| radare2           | `~/.codex/skills/radare2/SKILL.md`                |
| Firmware / IoT    | `~/.codex/skills/firmware-pentest/SKILL.md`       |
| PWN / Exploit     | `~/.codex/skills/pwn-chain/SKILL.md`              |
| Patch diff / Nday | `~/.codex/skills/patch-diff-exploit/SKILL.md`     |
| Binary diff       | `~/.codex/skills/binary-diff/SKILL.md`            |
| EDR bypass        | `~/.codex/skills/edr-bypass-re/SKILL.md`          |
| .NET binary       | `~/.codex/skills/dotnet-reverse/SKILL.md`         |
| JS reversing      | `~/.codex/skills/js-reverse/SKILL.md`             |
| Pentest tools     | `~/.codex/skills/pentest-tools/SKILL.md`          |
| Malware analysis  | `~/.codex/skills/malware-analysis/SKILL.md`       |

## Task Checklist (must pass before claiming completion)

- [ ] Ran `triage.py` or `ghidra_headless.py summary` on the target
- [ ] Loaded the format-specific SKILL.md from ~/.codex/skills/
- [ ] Used structured tools instead of manually guessing tool flags
- [ ] Produced a Logic Report with evidence-linked findings
- [ ] If tools were missing: analyzed with what's available, then offered to provision
- [ ] Did NOT execute untrusted samples
