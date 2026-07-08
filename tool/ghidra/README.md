# Ghidra Headless Java Scripts

Post-scripts for analyzeHeadless. Invoked via ghidra_headless.py.

| Script | Purpose |
|--------|---------|
| summary.java | Binary overview (name, language, image base) |
| functions.java | List functions by address and name |
| decompile.java | Decompile function at address to pseudo-C |
| strings.java | Search strings by substring |
| xrefs_to.java | Cross-references TO an address |
| xrefs_from.java | Cross-references FROM an address |
| finders.java | Function search (calling/string_refs) |

Usage: export GHIDRA_HOME=/path/to/ghidra then use ghidra_headless.py.
Requires JDK 17+.
