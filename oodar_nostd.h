// # oodar Freestanding Nostd Profile
//
// Logline: Bare-metal substrate providing zero-heap bump allocation, MMIO registers, and panic stubs without libc.
//
// Setup: Freestanding C11 with zero ambient authority and zero libc/pthread/landlock dependencies.
//
// Beats:
//   1. Zero-heap bump/arena allocator over static/fixed storage.
//   2. Volatile MMIO register read/write accessors with memory barriers.
//   3. Freestanding halt/panic stubs.

#ifndef OODAR_NOSTD_H
#define OODAR_NOSTD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OoNostdArena {
    uint8_t *buf;
    size_t capacity;
    size_t offset;
} OoNostdArena;

void oo_nostd_arena_init(OoNostdArena *arena, void *buf, size_t capacity);
void *oo_nostd_arena_alloc(OoNostdArena *arena, size_t size, size_t align);
void oo_nostd_arena_reset(OoNostdArena *arena);
size_t oo_nostd_arena_used(const OoNostdArena *arena);
size_t oo_nostd_arena_remaining(const OoNostdArena *arena);

void oo_nostd_global_init(void *buf, size_t capacity);
void *oo_nostd_alloc(size_t size, size_t align);
void oo_nostd_reset(void);
size_t oo_nostd_used(void);
size_t oo_nostd_remaining(void);

static inline void oo_mmio_barrier(void) {
    __asm__ volatile("" ::: "memory");
}

static inline uint8_t oo_mmio_read8(uintptr_t addr) {
    volatile const uint8_t *ptr = (volatile const uint8_t *)addr;
    uint8_t val = *ptr;
    oo_mmio_barrier();
    return val;
}

static inline void oo_mmio_write8(uintptr_t addr, uint8_t val) {
    oo_mmio_barrier();
    volatile uint8_t *ptr = (volatile uint8_t *)addr;
    *ptr = val;
}

static inline uint16_t oo_mmio_read16(uintptr_t addr) {
    volatile const uint16_t *ptr = (volatile const uint16_t *)addr;
    uint16_t val = *ptr;
    oo_mmio_barrier();
    return val;
}

static inline void oo_mmio_write16(uintptr_t addr, uint16_t val) {
    oo_mmio_barrier();
    volatile uint16_t *ptr = (volatile uint16_t *)addr;
    *ptr = val;
}

static inline uint32_t oo_mmio_read32(uintptr_t addr) {
    volatile const uint32_t *ptr = (volatile const uint32_t *)addr;
    uint32_t val = *ptr;
    oo_mmio_barrier();
    return val;
}

static inline void oo_mmio_write32(uintptr_t addr, uint32_t val) {
    oo_mmio_barrier();
    volatile uint32_t *ptr = (volatile uint32_t *)addr;
    *ptr = val;
}

static inline uint64_t oo_mmio_read64(uintptr_t addr) {
    volatile const uint64_t *ptr = (volatile const uint64_t *)addr;
    uint64_t val = *ptr;
    oo_mmio_barrier();
    return val;
}

static inline void oo_mmio_write64(uintptr_t addr, uint64_t val) {
    oo_mmio_barrier();
    volatile uint64_t *ptr = (volatile uint64_t *)addr;
    *ptr = val;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noreturn))
#endif
void oo_nostd_panic(const char *msg);

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noreturn))
#endif
void oo_nostd_abort(void);

#ifdef __cplusplus
}
#endif

#endif /* OODAR_NOSTD_H */
