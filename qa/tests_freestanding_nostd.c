// # qa/tests_freestanding_nostd.c — Freestanding Bare-Metal Profile Verification
//
// Logline: Proves zero-heap bump/arena allocator, MMIO register accessors, and panic stubs under freestanding profile.
//
// Setup: Standalone test linked against liboodar-nostd.a.
//
// Beats:
//   1. Zero-heap bump allocator over custom and global buffers.
//   2. Alignment invariants (8-byte, 16-byte, 64-byte alignment).
//   3. Fail-closed behavior on buffer exhaustion.
//   4. 8, 16, 32, 64-bit MMIO register read/write operations with memory barriers.
//   5. Freestanding abort in child process exits via signal/trap.

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../oodar_nostd.h"

static void test_arena_allocator(void) {
    uint8_t memory[512];
    OoNostdArena arena;
    oo_nostd_arena_init(&arena, memory, sizeof(memory));

    assert(oo_nostd_arena_used(&arena) == 0);
    assert(oo_nostd_arena_remaining(&arena) == sizeof(memory));

    void *p1 = oo_nostd_arena_alloc(&arena, 13, 8);
    assert(p1 != NULL);
    assert(((uintptr_t)p1 % 8) == 0);

    void *p2 = oo_nostd_arena_alloc(&arena, 25, 16);
    assert(p2 != NULL);
    assert(((uintptr_t)p2 % 16) == 0);
    assert((uint8_t *)p2 >= (uint8_t *)p1 + 13);

    void *p3 = oo_nostd_arena_alloc(&arena, 64, 64);
    assert(p3 != NULL);
    assert(((uintptr_t)p3 % 64) == 0);

    size_t remaining = oo_nostd_arena_remaining(&arena);
    void *too_big = oo_nostd_arena_alloc(&arena, remaining + 1, 8);
    assert(too_big == NULL);

    oo_nostd_arena_reset(&arena);
    assert(oo_nostd_arena_used(&arena) == 0);
    assert(oo_nostd_arena_remaining(&arena) == sizeof(memory));
}

static void test_global_allocator(void) {
    oo_nostd_reset();
    assert(oo_nostd_used() == 0);

    void *p = oo_nostd_alloc(128, 16);
    assert(p != NULL);
    assert(((uintptr_t)p % 16) == 0);
    assert(oo_nostd_used() >= 128);

    oo_nostd_reset();
    assert(oo_nostd_used() == 0);
}

static void test_mmio_registers(void) {
    uint8_t r8 = 0;
    oo_mmio_write8((uintptr_t)&r8, 0x5A);
    assert(oo_mmio_read8((uintptr_t)&r8) == 0x5A);

    uint16_t r16 = 0;
    oo_mmio_write16((uintptr_t)&r16, 0x1234);
    assert(oo_mmio_read16((uintptr_t)&r16) == 0x1234);

    uint32_t r32 = 0;
    oo_mmio_write32((uintptr_t)&r32, 0xDEADBEEF);
    assert(oo_mmio_read32((uintptr_t)&r32) == 0xDEADBEEF);

    uint64_t r64 = 0;
    oo_mmio_write64((uintptr_t)&r64, 0x0123456789ABCDEFULL);
    assert(oo_mmio_read64((uintptr_t)&r64) == 0x0123456789ABCDEFULL);

    oo_mmio_barrier();
}

static void test_abort_trap(void) {
    pid_t pid = fork();
    if (pid == 0) {
        oo_nostd_abort();
        exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    assert(WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) != 0));
}

int main(void) {
    test_arena_allocator();
    test_global_allocator();
    test_mmio_registers();
    test_abort_trap();
    printf("PASS: tests_freestanding_nostd\n");
    return 0;
}
