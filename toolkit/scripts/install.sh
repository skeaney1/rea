#!/usr/bin/env bash
# Install the free reverse-engineering suite on Ubuntu 24.04 (cloud container or WSL).
# Idempotent: re-running skips what is already present. Needs root (or sudo).
# Sources: apt, PyPI, crates.io, Maven Central and `git clone`. No paid tools.
# This is an opt-in analyst toolkit, separate from `rea setup`. It prints its
# plan and asks before changing anything; pass --yes for unattended runs
# (for example a cloud environment setup script). It never installs Node.js,
# npm or Ghidra, which REA treats as bring-your-own.
set -euo pipefail

PREFIX="${RE_PREFIX:-/opt/re}"
VENV="$PREFIX/venv"
BIN=/usr/local/bin
JADX_VERSION="${JADX_VERSION:-1.5.6}"

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

log() { printf '\n==> %s\n' "$*"; }

confirm_plan() {
  cat <<EOF
This will install, system-wide:
  - apt packages: build tools, a headless JDK (for apktool), gdb, QEMU user-mode,
    YARA, UPX, binwalk, squashfs/7-Zip/simg2img/dtc, apktool, WABT, tshark, sigrok-cli
  - a Python venv at $VENV with capa, FLOSS, Detect It Easy, angr, Qiling,
    Unicorn, Speakeasy, pwntools, LIEF, Frida, objection, androguard, qbindiff,
    ghidriff, mitmproxy and others, linked into $BIN
  - from source: capa rules, pycdc and radare2 under $PREFIX/src
  - jadx $JADX_VERSION from Maven (skipped if unreachable) and binwalk v3 via cargo
EOF
  [ "${1:-}" = "--yes" ] && return
  printf 'Proceed? [y/N] '
  read -r answer
  [ "$answer" = "y" ] || [ "$answer" = "Y" ] || { echo "Nothing changed."; exit 2; }
}

install_apt() {
  log "apt packages"
  $SUDO apt-get update -qq
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq --no-install-recommends \
    build-essential cmake meson ninja-build pkg-config git curl unzip jq maven \
    python3-venv python3-dev default-jdk-headless \
    file xxd hexyl binutils-multiarch gdb gdb-multiarch strace ltrace \
    yara upx-ucl qemu-user-static \
    binwalk squashfs-tools p7zip-full android-sdk-libsparse-utils device-tree-compiler \
    apktool wabt tshark sigrok-cli \
    libssl-dev libffi-dev libmagic1 >/dev/null
}

install_python() {
  log "Python tools in $VENV"
  $SUDO mkdir -p "$PREFIX"
  [ -x "$VENV/bin/python" ] || $SUDO python3 -m venv "$VENV"
  $SUDO "$VENV/bin/pip" install -q --upgrade pip wheel
  # Triage, formats, emulation, symbolic execution, diffing, mobile, network.
  $SUDO "$VENV/bin/pip" install -q \
    flare-capa flare-floss die-python yara-python \
    lief pefile pyelftools dnfile capstone keystone-engine unicorn \
    pwntools ropgadget checksec.py \
    angr qiling speakeasy-emulator \
    qbindiff ghidriff \
    frida-tools objection androguard \
    oletools decompyle3 kaitaistruct \
    mitmproxy
  # qiling and unicorn still import pkg_resources, which setuptools 81 removed.
  $SUDO "$VENV/bin/pip" install -q "setuptools<81"
  $SUDO install -m 755 "$(dirname "$0")/diec.py" "$BIN/diec"
  local tool
  for tool in capa floss yara-python ROPgadget checksec qbindiff ghidriff \
              frida frida-ps frida-trace objection androguard \
              olevba decompyle3 mitmproxy mitmdump speakeasy pwn; do
    [ -x "$VENV/bin/$tool" ] && $SUDO ln -sf "$VENV/bin/$tool" "$BIN/$tool"
  done
}

install_git_sources() {
  log "capa rules and pycdc from source"
  $SUDO mkdir -p "$PREFIX/src"
  if [ ! -d "$PREFIX/capa-rules/.git" ]; then
    $SUDO git clone -q --depth 1 https://github.com/mandiant/capa-rules "$PREFIX/capa-rules"
  fi
  if [ ! -x "$BIN/pycdc" ]; then
    [ -d "$PREFIX/src/pycdc/.git" ] || $SUDO git clone -q --depth 1 https://github.com/zrax/pycdc "$PREFIX/src/pycdc"
    $SUDO cmake -S "$PREFIX/src/pycdc" -B "$PREFIX/src/pycdc/build" -DCMAKE_BUILD_TYPE=Release >/dev/null
    $SUDO cmake --build "$PREFIX/src/pycdc/build" -j"$(nproc)" >/dev/null
    $SUDO install -m 755 "$PREFIX/src/pycdc/build/pycdc" "$PREFIX/src/pycdc/build/pycdas" "$BIN/"
  fi
}

# Current radare2 from git (Ubuntu ships 5.5 from 2021). Rizin is not used: its
# meson build downloads tarballs from github.com, which some sandboxes block.
install_radare2() {
  r2 -v 2>/dev/null | grep -q '^radare2 [6-9]' && return
  log "radare2 from source"
  [ -d "$PREFIX/src/radare2/.git" ] || $SUDO git clone -q --depth 1 https://github.com/radareorg/radare2 "$PREFIX/src/radare2"
  (cd "$PREFIX/src/radare2" && $SUDO ./configure --prefix=/usr/local >/dev/null \
    && $SUDO make -j"$(nproc)" >/dev/null && $SUDO make install >/dev/null)
  $SUDO ldconfig
}

install_jadx() {
  [ -x "$BIN/jadx" ] && return
  log "jadx $JADX_VERSION from Maven Central"
  local dir="$PREFIX/jadx" work
  work="$(mktemp -d)"
  cat >"$work/pom.xml" <<EOF
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>local</groupId><artifactId>jadx-fetch</artifactId><version>1</version>
<dependencies><dependency><groupId>io.github.skylot</groupId><artifactId>jadx-cli</artifactId>
<version>$JADX_VERSION</version></dependency></dependencies></project>
EOF
  $SUDO mkdir -p "$dir/lib"
  # Some jadx dependencies live on Google Maven; add it, and skip jadx if unreachable.
  sed -i 's#</dependencies>#</dependencies><repositories><repository><id>google</id><url>https://maven.google.com</url></repository></repositories>#' "$work/pom.xml"
  if ! (cd "$work" && mvn -q dependency:copy-dependencies -DoutputDirectory="$work/lib" >/dev/null 2>&1); then
    echo "jadx skipped: Maven Central or Google Maven unreachable (use androguard + apktool here)"
    rm -rf "$work"; return 0
  fi
  $SUDO cp "$work"/lib/*.jar "$dir/lib/"
  rm -rf "$work"
  $SUDO tee "$BIN/jadx" >/dev/null <<EOF
#!/bin/sh
exec java -cp "$dir/lib/*" jadx.cli.JadxCLI "\$@"
EOF
  $SUDO chmod 755 "$BIN/jadx"
}

install_rust() {
  command -v cargo >/dev/null || return 0
  log "binwalk v3 (Rust) from crates.io"
  command -v binwalk3 >/dev/null && return
  cargo install -q binwalk --root "$PREFIX/cargo" 2>/dev/null \
    && $SUDO ln -sf "$PREFIX/cargo/bin/binwalk" "$BIN/binwalk3" \
    || echo "binwalk v3 build failed; apt binwalk 2.x remains available"
}

confirm_plan "${1:-}"
install_apt
install_python
install_git_sources
install_radare2
install_jadx
install_rust
log "done; run scripts/verify-tools.sh"
