//! oodar/sec/cap/zig/cap_check.zig — Memory-safe cap bit check.
//!
//! Phase 4 sample: the leaf integer comparison that powers every
//! `oo_cap_require_*` gate. The current C implementation is:
//!
//!   if (got == 0 || got != want) { fail(); }
//!
//! In Zig, this is bounds-checked by construction: integer overflow
//! is a compile error in Debug, runtime-trapped in ReleaseSafe, and
//! documented as wrapping in ReleaseFast. The compare-then-branch is
//! explicit (no UB). The `fail` callback calls back into the C
//! oodar fail-closed path (blackbox_trap_cap + fprintf + exit).
//!
//! FFI signature matches the C convention so the umbrella can call
//! this from C with `oo_cap_check_bits_zig(cap, want)`.

/// C ABI: oo_cap_check_bits_zig(cap: i64, want: i64) -> i32 (1 == match, 0 == mismatch).
/// Returns 1 only when cap is non-zero AND cap == want. Anything else is 0.
/// The C side handles the fail-closed exit; this function is pure.
export fn oo_cap_check_bits_zig(cap: i64, want: i64) callconv(.c) i32 {
    if (cap == 0) return 0;
    if (cap != want) return 0;
    return 1;
}
