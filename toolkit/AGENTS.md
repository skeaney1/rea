# AGENTS.md

Rules for any agent (Claude Code, Codex, Cursor, others) doing reverse engineering
(RE) work with this toolkit. The root [AGENTS.md](../AGENTS.md) governs developing
REA itself; this file governs _using_ REA and the free tools around it to analyse
a target. Follow the process below in order. Do not skip a phase
because a later tool looks faster: each phase decides which tools the next one
needs and stops wasted work on the wrong target.

## Scope and authority

- Analyse only targets the owner is entitled to analyse: their own software and
  devices, software whose licence permits it, CTF challenges, or authorised
  security work. If ownership or authorisation is unclear, stop and ask.
- Every tool here is free. Binary Ninja is the owner's own licence and runs on
  their PC; never assume a paid tool is available anywhere else.
- Read-only by default. Patching, unpacking in place, or running a target is a
  separate, explicit step (Phase 5 and Phase 8) that needs the owner's go-ahead
  for each target.

## Evidence rules

Every claim in notes and reports carries one label. These are REA's own
categories (observations, derivations, inferences, unknowns), so REA Evidence and
external tool output share one vocabulary:

| Label        | Meaning                                   | Example                                   |
| ------------ | ----------------------------------------- | ----------------------------------------- |
| **Observed** | A tool printed it, or a run produced it   | `diec`: "UPX 4.x"                         |
| **Derived**  | Mechanically follows from observations    | Entropy 7.9 + UPX stub → packed           |
| **Inferred** | Analyst judgement from evidence           | "Function at 0x4012a0 parses the config"  |
| **Unknown**  | Not established; say what would settle it | "Key source unknown; needs Phase 5 trace" |

- Record the tool, version and exact command for every Observed fact. For REA
  results, cite the REA Evidence id instead.
- Never upgrade Inferred to Observed by repetition. Never report absence when a
  tool simply did not cover the region (say "not examined").
- Hash the original target (SHA-256) before any work. Work on copies; the
  original never changes.

## Case layout

One folder per target under `toolkit/cases/` (only `NOTES.md` and `REPORT.md`
are committed):

```
cases/<yyyy-mm-dd>-<short-name>/
  original/      untouched target, read-only (chmod a-w)
  work/          extracted, unpacked or patched copies
  out/           raw tool output, one file per command
  NOTES.md       running log: phase, command, finding, label
  REPORT.md      final answer (Phase 7)
```

Never commit binaries, firmware, captures, credentials or licence files.

## The process

### Phase 0: Question

Write the analyst question in `NOTES.md` before running anything: _what do we
need to know, and what answer ends the work?_ ("What does `--sync` send, and to
which host?" not "analyse this binary".) Every later phase is judged against it.

### Phase 1: Triage (always, minutes)

Identify the target before opening a decompiler.

| Step                                     | Tool                    | Command                               |
| ---------------------------------------- | ----------------------- | ------------------------------------- |
| Hash and type                            | `sha256sum`, `file`     | `sha256sum t; file t`                 |
| Compiler, packer, protector              | **Detect It Easy**      | `diec -d t` (`-j` for JSON)           |
| Capabilities                             | **capa**                | `capa -r /opt/re/capa-rules t`        |
| Strings, including decoded/stack strings | **FLOSS**               | `floss t` (`strings -n 6` for non-PE) |
| Known patterns                           | **YARA**                | `yara -r rules/ t`                    |
| Hardening                                | `checksec`              | `checksec --file t`                   |
| Headers and sections                     | `r2` / `readelf` / LIEF | `r2 -q -c 'iI;iS;ii' t`               |

capa and YARA matches are leads, not facts: a match is Observed, what it means
is Inferred until Phase 3 confirms the code (capa reports "parse credit card
information" on `/usr/bin/ls`).

Gate: you can state format, architecture, language/compiler, packed or not,
and the 3 to 5 capabilities most relevant to the question. If packed or a
container, go to Phase 2; otherwise Phase 3.

### Phase 2: Unpack and extract

| Target                        | Tool                                                          |
| ----------------------------- | ------------------------------------------------------------- |
| UPX-packed                    | `upx -d -o work/t.unpacked original/t`                        |
| Firmware blobs                | `binwalk -e` (v2) or `binwalk3 -e`, then `unsquashfs`, `7z x` |
| Android sparse / super images | `simg2img`, then mount or `7z x`                              |
| Device tree blobs             | `dtc -I dtb -O dts`                                           |
| APK / AAB                     | `apktool d` (resources, smali), `jadx -d` (Java)              |
| Python `.pyc` / frozen apps   | `pycdc`, `decompyle3`                                         |
| WebAssembly                   | `wasm2wat`, `wasm-objdump -x`                                 |
| Custom packer                 | Emulate to the unpacked state (Phase 5), then dump            |

Gate: every analysable component is in `work/` with its hash recorded, and each
one has been through Phase 1 triage.

### Phase 3: Static analysis

Pick the tool by job, not habit:

| Job                                         | Primary                                                                                                                                           | Alternative                                                                               |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Agent-driven analysis with cited Evidence   | **REA MCP**: `open_binary` once per target, then `search_strings`, `xrefs`, `analyze_function`, `procedure_pseudo_code`; `close_binary` when done | REA CLI (re-imports the target on every call, so use it only when an MCP tool is missing) |
| Interactive decompilation, scripting, types | **Binary Ninja** (owner's PC; MCP server for agents)                                                                                              | Ghidra (PC)                                                                               |
| Headless/batch analysis in a container      | `r2` (radare2), Ghidra headless (PC)                                                                                                              | angr CFG                                                                                  |
| Quick disassembly of a range                | `r2 -q -c 'aaa;pdf @ main' t`, `objdump -d`                                                                                                       | `gdb-multiarch`                                                                           |
| Android / Java                              | `jadx` (WSL/PC; see note)                                                                                                                         | `androguard`, `apktool d` (smali); Binary Ninja for native `.so`                          |
| .NET                                        | ILSpy / dnSpyEx (PC)                                                                                                                              | `dnfile` (Python)                                                                         |
| Python bytecode                             | `pycdc`                                                                                                                                           | `decompyle3`                                                                              |
| Office macros                               | `olevba`                                                                                                                                          |                                                                                           |
| Unknown data formats                        | ImHex (PC), `kaitaistruct`                                                                                                                        | `hexyl`, `xxd`                                                                            |

Method:

1. Start from the question's anchor: an import (`connect`, `CreateFileW`), a
   string from Phase 1, an exported symbol, or a capa match address.
2. Walk cross-references outward; rename and type as you go. In Binary Ninja,
   save the `.bndb` so annotations persist across sessions.
3. Identify library code first (Binary Ninja WARP/signatures, Ghidra
   FunctionID) and skip it.
4. Log each function you understand in `NOTES.md` with address and label.

Gate: the code path that answers the question is identified, or you can name
precisely what static analysis cannot resolve (indirect calls, encrypted data,
runtime-generated code). The second case goes to Phase 5.

### Phase 4: Diff (when two versions exist)

Use when the question is "what changed" (patch, update, fixed bug, variant).

| Tool                     | Use                                                                             |
| ------------------------ | ------------------------------------------------------------------------------- |
| **REA**                  | `compare_functions`, `compare_artifacts`, `find_changed_behavior` with Evidence |
| **qbindiff**             | Function matching from BinExport/Quokka exports                                 |
| **ghidriff**             | Ghidra-based diff with Markdown report (needs Ghidra on the PC)                 |
| **radiff2**              | Fast byte/function diff in the container: `radiff2 -AC a b`                     |
| BinDiff + BinExport (PC) | GUI diff; BinExport plugins exist for Binary Ninja and Ghidra                   |

Gate: a list of changed functions, each with a one-line Inferred meaning.

### Phase 5: Dynamic analysis (needs explicit go-ahead per target)

Never run an untrusted target on the host. In order of preference:

| Situation                                                      | Tool                                                                                                                                              |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Single function or decoder routine                             | `unicorn` / angr `SimulationManager` (no OS needed)                                                                                               |
| Foreign-architecture Linux binary                              | `qemu-<arch>-static -g 1234 t` + `gdb-multiarch`                                                                                                  |
| Whole program, sandboxed syscalls                              | `qiling` with the matching rootfs                                                                                                                 |
| Windows shellcode or PE, no Windows host                       | `speakeasy`                                                                                                                                       |
| Native Linux program you trust enough to run                   | `strace -f`, `ltrace`, `gdb` (pwndbg) inside a throwaway container                                                                                |
| Android / iOS / desktop app hooks                              | `frida-trace`, `frida`, `objection` on a test device or emulator                                                                                  |
| Windows                                                        | x64dbg, WinDbg (time travel), Process Monitor, in a VM on the PC                                                                                  |
| "Which input reaches this branch?"                             | angr symbolic execution                                                                                                                           |
| Process, browser, Electron, Frida or ADB capture with Evidence | REA's runtime workflows ([process capture](../docs/process-capture.md), [Frida](../docs/frida-instrumentation.md)); each guide states its effects |

Record every run: command, environment, inputs, and output files in `out/`.
Gate: the runtime facts the static phase lacked are Observed.

### Phase 6: Network and protocol

| Data                      | Tool                                                                     |
| ------------------------- | ------------------------------------------------------------------------ |
| Live HTTP(S)              | `mitmdump -w out/flows` (or `mitmproxy`)                                 |
| Packet captures           | `tshark -r cap.pcapng -q -z conv,tcp`, field extraction with `-T fields` |
| Logic analyser recordings | `sigrok-cli -i rec.sr -P <decoder>` (PulseView on the PC)                |

Map each message back to the code that builds or parses it (Phase 3 address).

### Phase 7: Report

`REPORT.md` answers the Phase 0 question first, in plain language, then:
evidence table (fact, label, tool, command, address/offset), remaining
Unknowns with what would settle each, and reproduction steps. Keep it short:
the evidence is in `out/` and `NOTES.md`.

### Phase 8: Change (only if asked)

Patching or reimplementing is separate from understanding. Patch copies in
`work/`, never `original/`. Re-run Phase 1 on the patched file and prove the
change with a before/after run.

## Where each tool runs

| Container / WSL (installed by `toolkit/scripts/install.sh`)    | Owner's Windows PC (install by hand, all free)        |
| -------------------------------------------------------------- | ----------------------------------------------------- |
| diec, capa, FLOSS, YARA, checksec, LIEF                        | **Binary Ninja** (owned), Ghidra, BinDiff + BinExport |
| binwalk 2/3, upx, unsquashfs, simg2img, dtc, 7z                | x64dbg, WinDbg, Process Monitor, API Monitor          |
| radare2, objdump, apktool, androguard, pycdc, decompyle3, wabt | jadx, dnSpyEx, ILSpy, ImHex, PulseView                |
| gdb, gdb-multiarch, strace, ltrace, qemu-user-static           | Wireshark, a VM for running untrusted samples         |
| angr, qiling, unicorn, speakeasy, pwntools, frida, objection   |                                                       |
| qbindiff, ghidriff, radiff2, tshark, mitmproxy, sigrok-cli     |                                                       |

Check the container with `toolkit/scripts/verify-tools.sh` before starting a case. A
missing tool is a blocker to report, not a reason to substitute silently.

Known container limits (sandboxed cloud sessions block github.com downloads
and Google Maven): jadx cannot be fetched there, so `install.sh` skips it and it
works on WSL or the PC; Rizin is not built, radare2 6.x covers the same ground.
Ghidra stays bring-your-own, as REA requires; the installer never installs it.

## Efficiency rules for agents

- Run Phase 1 tools in one batch and keep outputs in `out/`; read summaries,
  not full dumps (`capa` default view, not `-vv`, unless a match needs detail).
- Prefer JSON output (`diec -j`, `capa -j`, `r2` `j` suffix) when another
  tool or script consumes it.
- Answer the Phase 0 question with the smallest sufficient evidence. Stop when
  it is answered; list further leads as Unknowns instead of chasing them.
