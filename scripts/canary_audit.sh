#!/bin/sh
# oodar/scripts/canary_audit.sh — Stack-canary coverage audit (Task E.4).
#
# Method: extract oodar.o from liboodar.a, run objdump -dr to get all
# functions + their relocations. A function is "stack-protected" if
# it has at least one PLT32 relocation to __stack_chk_fail.
#
# Then check the high-risk functions (per docs/SECURITY_MODEL.oot
# Beat 5 + the 2026-09-11 focused audit, audit/2026-09-11-focused-
# oodar.oot — F1 finding): any function that takes OoStr (untrusted
# length-prefixed string) AND copies bytes into a stack buffer MUST
# be stack-protected. -fstack-protector-strong (in scripts/Makefile)
# covers this for most functions; we verify the audit catches any
# regression.
#
# Output: prints PROTECTED/MISSING for each high-risk function,
# plus the total protected count. Exit 0 = all high-risk functions
# are protected. Exit 1 = at least one high-risk function is missing
# the canary.

set -e
cd "$(dirname "$0")"
LIB=lib/liboodar.a
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

# Extract the umbrella .o.
cp "$LIB" "$TMP/"
(cd "$TMP" && ar x liboodar.a oodar.o)
OBJ="$TMP/oodar.o"

# List of high-risk functions. Per the 2026-09-11 focused audit + docs:
#   - any oo_* that takes OoStr + copies into PATH_MAX / OO_PATH_CAP_MAX_PREFIX / etc.
#   - any oo_* that calls oo_str_alloc_payload + memcpy
#   - the cap-attenuate wrappers (HMAC into stack buffers)
HIGH_RISK="oo_str_alloc_payload oo_read_file oo_read_stdin_chunk \
  oo_attenuate_fsread_to_path oo_cap_attenuate_v2 oo_env_get \
  oo_seal oo_open oo_dlopen oo_lto_xlang_link oo_audio_capture \
  oo_fs_read_dir oo_audio_init oo_path_cap_check"

# Get the set of stack-protected functions.
PROTECTED="$TMP/protected.txt"
objdump -dr "$OBJ" 2>/dev/null \
  | awk '/^[0-9a-f]+ </{fn=$NF; sub(/>:$/,"",fn)} /__stack_chk_fail/{print fn}' \
  | sort -u > "$PROTECTED"

# Also get total function count + protected count for the report.
TOTAL=$(objdump -d "$OBJ" 2>/dev/null | grep -cE '^[0-9a-f]+ <')
PROT_COUNT=$(wc -l < "$PROTECTED")

# Audit.
FAIL=0
echo "Stack-canary audit (Task E.4, v4.9.0)"
echo "  Total functions: $TOTAL"
echo "  Protected:        $PROT_COUNT ($(( PROT_COUNT * 100 / TOTAL ))%)"
echo
echo "High-risk function coverage:"
for fn in $HIGH_RISK; do
  if grep -qx "<$fn" "$PROTECTED"; then
    echo "  PROTECTED: $fn"
  else
    echo "  MISSING:   $fn"
    FAIL=$((FAIL + 1))
  fi
done

echo
if [ $FAIL -eq 0 ]; then
  echo "AUDIT OK: all high-risk functions are stack-protected"
  exit 0
else
  echo "AUDIT FAIL: $FAIL high-risk function(s) missing canary"
  exit 1
fi
