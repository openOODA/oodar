//! oodar/sec/cap/zig/cap_check_test.zig — Unit tests for cap_check.
//!
//! Compile-time test: prove the bit-check semantics via Zig's
//! built-in test runner. `zig build test` runs these.

const std = @import("std");
const testing = std.testing;

// Pull the function under test by importing the sibling module.
// In Zig, each .zig file is its own compilation unit by default; for
// a static lib + test split, we duplicate the export in a test-only
// shim. (Zig doesn't currently allow `test` blocks in static-library
// roots without `addTest` finding them — so we keep tests separate.)

extern fn oo_cap_check_bits_zig(cap: i64, want: i64) callconv(.c) i32;

test "cap zero is mismatch" {
    try testing.expectEqual(@as(i32, 0), oo_cap_check_bits_zig(0, 12345));
}

test "cap equal to want is match" {
    try testing.expectEqual(@as(i32, 1), oo_cap_check_bits_zig(12345, 12345));
}

test "cap non-zero but unequal is mismatch" {
    try testing.expectEqual(@as(i32, 0), oo_cap_check_bits_zig(12345, 99999));
}

test "negative cap (forge attempt) is mismatch unless equal to want" {
    try testing.expectEqual(@as(i32, 0), oo_cap_check_bits_zig(-1, 12345));
    try testing.expectEqual(@as(i32, 1), oo_cap_check_bits_zig(-1, -1));
}

test "i64 extremes are well-defined" {
    const i64_max: i64 = std.math.maxInt(i64);
    const i64_min: i64 = std.math.minInt(i64);
    try testing.expectEqual(@as(i32, 0), oo_cap_check_bits_zig(i64_max, 0));
    try testing.expectEqual(@as(i32, 1), oo_cap_check_bits_zig(i64_max, i64_max));
    try testing.expectEqual(@as(i32, 0), oo_cap_check_bits_zig(i64_min, 0));
    try testing.expectEqual(@as(i32, 1), oo_cap_check_bits_zig(i64_min, i64_min));
}
