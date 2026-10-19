# Analyst toolkit

A free reverse-engineering suite that sits around REA, plus the process for
using them together. It is separate from `rea setup` and installs nothing
unless you run it.

- [`AGENTS.md`](AGENTS.md): the analysis process (Phases 0 to 8) every agent
  follows here. `CLAUDE.md` imports it for Claude Code.
- `scripts/install.sh`: installs the container/WSL tools on Ubuntu 24.04 from
  apt, PyPI, crates.io, Maven Central and git. It prints its plan and asks
  first; `--yes` skips the prompt. Idempotent.
- `scripts/verify-tools.sh`: lists what is installed; exits 1 if anything is
  missing.
- `cases/`: one folder per target. Only `NOTES.md` and `REPORT.md` are
  committed.
- `rules/`: your own YARA rules.

## Cloud sessions

Tools installed in a cloud container vanish when it is reclaimed. To have them
in every session, add this to the environment's **Setup script**:

```sh
git clone --depth 1 https://github.com/skeaney1/rea /opt/rea-toolkit \
  && bash /opt/rea-toolkit/toolkit/scripts/install.sh --yes
```

## Windows PC (manual, all free)

Ghidra, BinDiff + BinExport, x64dbg, WinDbg, Process Monitor, API Monitor,
dnSpyEx, ILSpy, ImHex, PulseView and Wireshark. Binary Ninja is already owned.
