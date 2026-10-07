// # oodar Freestanding Nostd Implementation
//
// Logline: Zero-heap bump allocator, static arena storage, and panic stubs for bare-metal targets.
//
// Setup: Freestanding C11. No libc, no pthreads, no Landlock.
//
// Beats:
//   1. Arena bump allocator with alignment padding.
//   2. Global static backing buffer for zero-heap runtime.
//   3. Non-returning panic and abort stubs.

#include "oodar_nostd.h"

#define OO_NOSTD_DEFAULT_CAPACITY (64 * 1024)
static uint8_t s_default_buf[OO_NOSTD_DEFAULT_CAPACITY];
static OoNostdArena s_global_arena = {
    .buf = s_default_buf,
    .capacity = OO_NOSTD_DEFAULT_CAPACITY,
    .offset = 0
};

void oo_nostd_arena_init(OoNostdArena *arena, void *buf, size_t capacity) {
    if (!arena) return;
    arena->buf = (uint8_t *)buf;
    arena->capacity = capacity;
    arena->offset = 0;
}

void *oo_nostd_arena_alloc(OoNostdArena *arena, size_t size, size_t align) {
    if (!arena || !arena->buf || size == 0) return (void *)0;
    if (align == 0) align = sizeof(void *);

    uintptr_t current_addr = (uintptr_t)(arena->buf + arena->offset);
    uintptr_t aligned_addr = (current_addr + (align - 1)) & ~(align - 1);
    size_t pad = (size_t)(aligned_addr - current_addr);

    if (arena->offset + pad + size > arena->capacity) {
        return (void *)0;
    }

    arena->offset += pad + size;
    return (void *)aligned_addr;
}

void oo_nostd_arena_reset(OoNostdArena *arena) {
    if (arena) {
        arena->offset = 0;
    }
}

size_t oo_nostd_arena_used(const OoNostdArena *arena) {
    return arena ? arena->offset : 0;
}

size_t oo_nostd_arena_remaining(const OoNostdArena *arena) {
    if (!arena || arena->offset >= arena->capacity) return 0;
    return arena->capacity - arena->offset;
}

void oo_nostd_global_init(void *buf, size_t capacity) {
    oo_nostd_arena_init(&s_global_arena, buf, capacity);
}

void *oo_nostd_alloc(size_t size, size_t align) {
    return oo_nostd_arena_alloc(&s_global_arena, size, align);
}

void oo_nostd_reset(void) {
    oo_nostd_arena_reset(&s_global_arena);
}

size_t oo_nostd_used(void) {
    return oo_nostd_arena_used(&s_global_arena);
}

size_t oo_nostd_remaining(void) {
    return oo_nostd_arena_remaining(&s_global_arena);
}

void oo_nostd_abort(void) {
#if defined(__has_builtin) && __has_builtin(__builtin_trap)
    __builtin_trap();
#else
    volatile int *trap = (volatile int *)0;
    (void)*trap;
    while (1) {
        __asm__ volatile("" ::: "memory");
    }
#endif
}

void oo_nostd_panic(const char *msg) {
    (void)msg;
    oo_nostd_abort();
}
