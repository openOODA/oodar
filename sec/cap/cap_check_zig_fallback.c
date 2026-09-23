/* sec/cap/cap_check_zig_fallback.c — Phase 4 C fallback for the
 * cap-system leaf bit check.
 *
 * Originally authored in Zig (sec/cap/zig/cap_check.zig, deleted
 * 2026-09-11 — see git history and anchor.oo for that directory).
 * That file violated RULES §1.14 (no .zig carve-out) and §1.23
 * (oodar/* is "Layer 1 C shims and Landlock sandbox" — explicitly C
 * only). This TU provides the same leaf logic in plain C.
 *
 * Function: oo_cap_check_bits(cap, want) -> int
 *   Returns 1 iff cap is non-zero AND cap == want.
 *   Returns 0 otherwise (fail-closed on absence or mismatch).
 *
 * C ABI: `int oo_cap_check_bits(long long cap, long long want)`.
 *   The Zig version used the same signature. Any future Zig /
 *   Rust / Go rewrite (per an RFC carving out a new file extension)
 *   can call this function via FFI during the migration; the
 *   semantics are the reference implementation.
 *
 * This documents the leaf contract of every oo_cap_require_* gate —
 * the gates in sec/cap/cap_require.c implement it inline.
 */

#include "../../oodar.h"

/* Reference leaf logic (kept as documentation; no code emitted):
 *   nonzero cap AND cap == want -> 1, else 0 (fail-closed).
 * The former static oo_cap_check_bits() helper was deleted: it had
 * no callers (the gates in cap_require.c compare inline) and only
 * cost .text. Any future external caller should wrap this contract
 * in a proper public ABI symbol after the RFC for the cap-system
 * rewrite lands. */
