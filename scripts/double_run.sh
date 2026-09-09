#!/usr/bin/env bash
# Immune system, oodar half: run every challenger twice in fresh processes
# and require byte-identical stdout+stderr AND identical exit codes.
# AI writes the code; this machinery makes it trustworthy.
#
# Usage: ./scripts/double_run.sh  (run from the repo root)
# Fuzz probes run under a fixed argv seed so the double-run law applies.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
FAIL=0
PASS_N=0
say() { printf '[double-run] %s\n' "$*"; }

# Ensure binaries exist (also proves the suite passes once via make test).
if ! make -C scripts test > /tmp/oodar_doublerun_maketest.log 2>&1; then
  say "FAIL: make test failed; last 30 lines:"
  tail -n 30 /tmp/oodar_doublerun_maketest.log
  exit 1
fi
say "make test green; starting identical-twice loop"

run_twice() {
  local bin="$1"; shift
  "$bin" "$@" > /tmp/odr1.log 2>&1; local e1=$?
  "$bin" "$@" > /tmp/odr2.log 2>&1; local e2=$?
  if [[ "$e1" != "$e2" ]]; then
    say "FAIL: $bin exit differs ($e1 vs $e2)"; FAIL=1; return
  fi
  if ! cmp -s /tmp/odr1.log /tmp/odr2.log; then
    say "FAIL: $bin output differs across fresh runs"; FAIL=1; return
  fi
  PASS_N=$((PASS_N + 1))
  say "identical: $bin (exit $e1)"
}

# Exit-code-only: these mint unguessable crypto tokens (getentropy-backed by
# design — seeding them would weaken the security property under test), so
# byte-output legally differs while relations asserted in-test must hold.
# Anything else diverging is a real failure.
run_twice_exit_only() {
  local bin="$1"; shift
  "$bin" "$@" > /tmp/odr1.log 2>&1; local e1=$?
  "$bin" "$@" > /tmp/odr2.log 2>&1; local e2=$?
  if [[ "$e1" != "$e2" ]]; then
    say "FAIL: $bin exit differs ($e1 vs $e2)"; FAIL=1; return
  fi
  if [[ "$e1" != "0" ]]; then
    say "FAIL: $bin exited $e1"; FAIL=1; return
  fi
  PASS_N=$((PASS_N + 1))
  say "exit-identical (crypto-random output): $bin"
}

export OODAR_REPO="$ROOT"
for bin in scripts/build/test/* scripts/build/lint/*; do
  [[ -x "$bin" && -f "$bin" ]] || continue
  case "$bin" in
    *fuzz*) run_twice "$bin" 0x12345678 ;;
    *differential_cap*|*pathcap*) run_twice_exit_only "$bin" ;;
    *) run_twice "$bin" ;;
  esac
done

if [[ "$FAIL" != "0" ]]; then
  say "FAIL: $PASS_N identical, some diverged"
  exit 1
fi
say "PASS: all $PASS_N challengers byte-identical across fresh double-runs"
