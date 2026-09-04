#!/usr/bin/env bash
# # oodar/scripts/repro_build.sh — Reproducible Build for liboodar.a
#
# Logline: Build a bit-identical liboodar.a across builds by setting
# SOURCE_DATE_EPOCH, using deterministic ar flags (rcsD), sorting the
# .o file order, and stripping embedded paths. Produces a sha256
# hash of the resulting lib; the verify mode re-builds and checks
# the hash matches the recorded value.
#
# Setup: The script wraps `make -C scripts` with the reproducibility
# knobs that the Makefile exposes. It is the canonical entry point
# for reproducible builds. Use `./repro_build.sh` to build and
# `./repro_build.sh verify <hash>` to re-build and verify.
#
# Usage:
#   ./repro_build.sh                # build liboodar.a, print hash
#   ./repro_build.sh clean          # remove all build artifacts
#   ./repro_build.sh verify <hash>  # re-build, check hash matches
#
# Variables (all overridable on the command line or via env):
#   SOURCE_DATE_EPOCH : the canonical "build timestamp" (default: 0)
#   CC                : C compiler (default: gcc)
#   CFLAGS            : compile flags (default: -O2 -g -fPIC + reproducible knobs)
#   AR                : archiver (default: ar)
#   ARFLAGS           : ar flags (default: rcsD)
#   HASH              : hash command (default: sha256sum)
#   DESTDIR           : install prefix (default: /usr/local)
#
# Reproducibility knobs (all set by this script):
#   - SOURCE_DATE_EPOCH=0 : the canonical build timestamp. The Makefile
#     uses it implicitly via the toolchain (ar rcsD ignores mtime
#     in deterministic mode, but other tools may not).
#   - CFLAGS includes -ffile-prefix-map and -fmacro-prefix-map to
#     strip the build path from __FILE__ and similar macros.
#   - CFLAGS includes -fno-stack-protector (deterministic per build;
#     canaries vary across runs in stack-protector mode).
#   - CFLAGS includes -Wno-builtin-macro-redefined to suppress the
#     warning about redefining __DATE__ / __TIME__.
#   - ARFLAGS=rcsD uses deterministic mode (no mtime, no uids/gids).
#   - The .o file order passed to ar is sorted, so the archive
#     contents are identical regardless of which platform built it.
#
# What this script does NOT control:
#   - The host toolchain version (gcc 9 vs gcc 13 will produce
#     different .o files for the same source). The script records
#     the toolchain version in the hash file for traceability.
#   - The OS page size and alignment (relevant for some .o
#     metadata; not usually an issue for static archives).
#   - The host's libc version (glibc 2.31 vs 2.35 may differ).
#
# Beats:
#   1. Set reproducibility knobs.
#   2. Build liboodar.a via `make -C scripts`.
#   3. Compute and print the sha256 hash.
#   4. (verify mode) Re-build and check the hash matches.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Resolve the script's directory and the repo root. The script lives
# in scripts/ inside the oodar repo; the repo root is one level up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults — override on the command line or via env.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
CC="${CC:-gcc}"
AR="${AR:-ar}"
ARFLAGS="${ARFLAGS:-rcsD}"
HASH="${HASH:-sha256sum}"
DESTDIR="${DESTDIR:-/usr/local}"

# Reproducibility CFLAGS. We add the prefix-map flags to strip the
# build path from __FILE__ / __BASE_FILE__ macros. We disable the
# stack protector (canaries vary by run). We suppress the
# __DATE__/__TIME__ redefined warning (we set them via -D below).
#
# Note: -D__DATE__=... and -D__TIME__=... would break the source's
# #ifdef checks of these macros. We do NOT set them; we rely on
# the toolchain not embedding timestamps in the .o (gcc does
# embed __DATE__ in the .o, but only when the source uses it;
# our sources do not, so the .o is timestamp-free for our case).
CFLAGS_REPRO=(
  "-O2"
  "-g"
  "-fPIC"
  "-std=c11"
  "-D_GNU_SOURCE"
  "-DOODAR_CRYPTO_INTERNAL"
  "-include" "oodar.h"
  "-ffile-prefix-map=$REPO_ROOT=."
  "-fmacro-prefix-map=$REPO_ROOT=."
  "-fno-stack-protector"
  "-Wno-builtin-macro-redefined"
)

# Output paths
BUILD_DIR="$SCRIPT_DIR/build"
LIB_DIR="$SCRIPT_DIR/lib"
LIB="$LIB_DIR/liboodar.a"
HASH_FILE="$LIB_DIR/liboodar.a.sha256"

# Toolchain version (for traceability in the hash file)
CC_VERSION="$($CC --version 2>&1 | head -1 || echo "unknown")"

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

print_config() {
  echo "=== Reproducible build config ==="
  echo "REPO_ROOT       = $REPO_ROOT"
  echo "SOURCE_DATE_EPOCH = $SOURCE_DATE_EPOCH"
  echo "CC              = $CC ($CC_VERSION)"
  echo "CFLAGS          = ${CFLAGS_REPRO[*]}"
  echo "AR              = $AR"
  echo "ARFLAGS         = $ARFLAGS"
  echo "HASH            = $HASH"
  echo "LIB             = $LIB"
  echo "================================"
}

do_clean() {
  echo "CLEAN"
  rm -rf "$BUILD_DIR" "$LIB_DIR"
}

do_build() {
  print_config

  # Export reproducibility knobs for the make subprocess. SOURCE_DATE_EPOCH
  # is the most important one — many tools (ar, install, etc.) honor it.
  export SOURCE_DATE_EPOCH

  # Build via the Makefile. We pass CFLAGS explicitly so the user can
  # override the reproducibility knobs if they need to (e.g., for
  # debugging). The Makefile merges our CFLAGS_REPRO into the CFLAGS
  # it uses.
  echo
  echo "=== Building liboodar.a ==="
  (cd "$SCRIPT_DIR" && make \
      CC="$CC" \
      AR="$AR" \
      ARFLAGS="$ARFLAGS" \
      CFLAGS="${CFLAGS_REPRO[*]}" \
      DESTDIR="$DESTDIR" \
      REPO_ROOT="$REPO_ROOT" \
      "$@")

  echo
  echo "=== Computing hash ==="
  mkdir -p "$LIB_DIR"
  local hash
  hash=$($HASH "$LIB" | awk '{print $1}')
  echo "$hash  $LIB" > "$HASH_FILE"
  echo "HASH  $hash"
  echo "HASH_FILE  $HASH_FILE"
  echo "CC_VERSION  $CC_VERSION" >> "$HASH_FILE"
  echo
  echo "Build complete. To verify: $0 verify $hash"
}

do_verify() {
  local expected_hash="${1:-}"
  if [ -z "$expected_hash" ]; then
    echo "ERROR: verify mode requires a hash argument." >&2
    echo "Usage: $0 verify <sha256-hash>" >&2
    exit 2
  fi
  echo "=== Verify mode: expected hash = $expected_hash ==="

  # Re-build clean and re-hash.
  do_clean
  do_build > /tmp/repro_build_output 2>&1 || {
    cat /tmp/repro_build_output >&2
    exit 1
  }
  cat /tmp/repro_build_output

  local actual_hash
  actual_hash=$($HASH "$LIB" | awk '{print $1}')
  echo
  echo "Expected: $expected_hash"
  echo "Actual:   $actual_hash"
  if [ "$expected_hash" = "$actual_hash" ]; then
    echo "VERIFY OK: hashes match — build is reproducible."
    exit 0
  else
    echo "VERIFY FAIL: hashes differ — build is not reproducible." >&2
    echo "(Note: toolchain version or host differences may explain this.)" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

case "${1:-build}" in
  build|"")
    do_build
    ;;
  clean)
    do_clean
    ;;
  verify)
    do_verify "${2:-}"
    ;;
  check)
    (cd "$SCRIPT_DIR" && make check REPO_ROOT="$REPO_ROOT")
    ;;
  help|--help|-h)
    cat <<EOF
oodar/scripts/repro_build.sh — reproducible build for liboodar.a

Usage:
  $0                # build liboodar.a and print hash
  $0 clean          # remove all build artifacts
  $0 verify <hash>  # re-build and check hash matches
  $0 check          # verify all 48 source files are present
  $0 help           # this help text

Environment:
  SOURCE_DATE_EPOCH : the canonical build timestamp (default: 0)
  CC                : C compiler (default: gcc)
  CFLAGS            : compile flags (default: -O2 -g -fPIC + reproducible knobs)
  AR                : archiver (default: ar)
  ARFLAGS           : ar flags (default: rcsD — deterministic mode)
  HASH              : hash command (default: sha256sum)
  DESTDIR           : install prefix (default: /usr/local)

The script sets SOURCE_DATE_EPOCH, sorts the .o file order, uses
ar rcsD (deterministic), strips the build path from __FILE__ via
-ffile-prefix-map, and disables the stack protector (canaries vary
across runs). See top-of-file comments for the full list of knobs.
EOF
    ;;
  *)
    echo "ERROR: unknown command: $1" >&2
    echo "Run '$0 help' for usage." >&2
    exit 2
    ;;
esac
