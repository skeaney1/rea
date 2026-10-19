#!/usr/bin/env bash
# Report which suite tools are installed and runnable. Exit 1 if any are missing.
set -uo pipefail

missing=0
check() {
  local name="$1"; shift
  # Pass when the tool prints something that is not a load error; some tools
  # exit non-zero for --version or --help, so the exit status is not used.
  out="$("$@" 2>&1 | grep -v -e '^Picked up JAVA_TOOL_OPTIONS' -e 'SyntaxWarning' -e '^Running as user' | head -1)"
  if [ -n "$out" ] && ! printf '%s' "$out" | grep -qiE 'not found|No module named|Traceback'; then
    printf '  ok   %-12s %s\n' "$name" "${out:0:70}"
  else
    printf '  MISS %-12s\n' "$name"; missing=$((missing + 1))
  fi
}

echo "Triage"
check file        file --version
check diec        diec --version
check capa        capa --version
check floss       floss --version
check yara        yara --version
check checksec    sh -c 'checksec /bin/ls | head -2 | tail -1'
echo "Unpacking"
check binwalk     sh -c 'binwalk --help 2>&1 | grep -m1 Binwalk'
check binwalk3    binwalk3 --version
check upx         upx --version
check simg2img    sh -c 'command -v simg2img'
check dtc         dtc --version
check unsquashfs  sh -c 'unsquashfs -v 2>&1 || true'
check 7z          sh -c '7z | sed -n 2p'
echo "Static"
check radare2     r2 -v
check objdump     objdump --version
check jadx        jadx --version
check apktool     apktool --version
check pycdc       sh -c 'command -v pycdc'
check decompyle3  decompyle3 --version
check wasm2wat    wasm2wat --version
check hexyl       hexyl --version
echo "Dynamic and emulation"
check gdb         gdb --version
check gdb-multi   gdb-multiarch --version
check strace      strace -V
check ltrace      ltrace -V
check qemu-arm64  qemu-aarch64-static --version
check frida       frida --version
check speakeasy   sh -c 'command -v speakeasy'
check pwntools    pwn version
echo "Diffing"
check qbindiff    qbindiff --help
check ghidriff    ghidriff --help
check radiff2     radiff2 -v
echo "Network and signals"
check tshark      tshark --version
check mitmdump    mitmdump --version
check sigrok-cli  sigrok-cli --version
echo "Python libraries"
check py-libs     /opt/re/venv/bin/python -c 'import warnings,logging;logging.disable(logging.ERROR);import angr,qiling,lief,pefile,elftools,capstone,unicorn,die,yara,androguard;print("angr qiling lief pefile elftools capstone unicorn die yara androguard")'

echo; echo "missing: $missing"
[ "$missing" -eq 0 ]
