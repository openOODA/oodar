// oodar/sec/cap/zig/build.zig — Zig build for oodar cap-system Phase 4.
//
// Builds the cap-system check (currently a single function, the leaf
// of the trust boundary) as a static library that the C umbrella can
// link against. Phase 4 sample: oo_cap_check_bits_zig — the leaf
// integer comparison that powers every oo_cap_require_* gate.
//
// Full Phase 4 (per the 2026-09-11 memory-safety plan): every cap-
// system .c file moves to Zig. This build.zig is the scaffold that
// makes incremental migration possible — one .zig at a time.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const cap_check = b.addStaticLibrary(.{
        .name = "oodar_cap_check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cap_check.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // C link flags — Zig uses libc for the cap_check extern callbacks
    // (fprintf, exit). Link against pthreads for any future threading.
    cap_check.linkLibC();
    if (target.result.os.tag == .linux) {
        cap_check.linkSystemLibrary("pthread");
    }

    b.installArtifact(cap_check);

    // Unit tests: prove the bit-check semantics via Zig's built-in
    // test runner. `zig build test` runs these. The test links
    // against the static library so the `extern fn oo_cap_check_bits_zig`
    // declaration in cap_check_test.zig resolves.
    const cap_check_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("cap_check_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    cap_check_tests.linkLibrary(cap_check);
    cap_check_tests.linkLibC();

    const test_step = b.step("test", "Run cap_check unit tests");
    test_step.dependOn(&b.addRunArtifact(cap_check_tests).step);
}
