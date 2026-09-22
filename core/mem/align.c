/* 64-byte aligned string/list payloads. Header layout is unchanged:
 * payload sits 64 bytes into the block; OoStrHeader/OoListHeader is
 * immediately before the payload (8-16 bytes). free() the 64-aligned block. */
#include "../../oodar.h"
#include <stdint.h>
#include <errno.h>

#ifndef OO_PAYLOAD_ALIGN
#define OO_PAYLOAD_ALIGN 64
#endif

extern int oo_arena_active_id(void);
extern void *oo_arena_alloc_payload(int slot, size_t hdr_sz, size_t payload_sz);

#include <sys/mman.h>
#define OO_LARGE_PAYLOAD_THRESHOLD 1048576
#define OO_MMAP_MAGIC 0x4D4D415053595300ULL

static __thread void *g_large_cached_blk = NULL;
static __thread size_t g_large_cached_sz = 0;
static __thread int g_large_cached_in_use = 0;

static void *oo_alloc_large_mmap(size_t n) {
  size_t map_sz = (n + 4095) & ~4095UL;
  if (!g_large_cached_in_use && g_large_cached_blk && g_large_cached_sz >= map_sz) {
    g_large_cached_in_use = 1;
#if defined(__linux__)
    if (g_large_cached_sz > 4096) {
      madvise((char *)g_large_cached_blk + 4096, g_large_cached_sz - 4096, MADV_DONTNEED);
    }
#endif
    *(uint64_t *)g_large_cached_blk = OO_MMAP_MAGIC;
    *(size_t *)((char *)g_large_cached_blk + 8) = g_large_cached_sz;
    return (char *)g_large_cached_blk + OO_PAYLOAD_ALIGN;
  }
  if (!g_large_cached_in_use && g_large_cached_blk && g_large_cached_sz < map_sz) {
    munmap(g_large_cached_blk, g_large_cached_sz);
    g_large_cached_blk = NULL;
    g_large_cached_sz = 0;
  }
  void *blk = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (blk == MAP_FAILED) abort();
  *(uint64_t *)blk = OO_MMAP_MAGIC;
  *(size_t *)((char *)blk + 8) = map_sz;
  if (!g_large_cached_blk) {
    g_large_cached_blk = blk;
    g_large_cached_sz = map_sz;
    g_large_cached_in_use = 1;
  }
  return (char *)blk + OO_PAYLOAD_ALIGN;
}

void *oo_payload_alloc_uninit(size_t hdr_sz, size_t payload_sz) {
  size_t n;
  void *blk = NULL;
  char *pay;
  (void)hdr_sz;
  if (payload_sz > (SIZE_MAX - OO_PAYLOAD_ALIGN - 1)) abort();
  int aid = oo_arena_active_id();
  if (aid >= 0) {
    void *p = oo_arena_alloc_payload(aid, hdr_sz, payload_sz);
    if (p) return p;
  }
  n = OO_PAYLOAD_ALIGN + payload_sz;
  if (n % OO_PAYLOAD_ALIGN) n += OO_PAYLOAD_ALIGN - (n % OO_PAYLOAD_ALIGN);
  if (payload_sz >= OO_LARGE_PAYLOAD_THRESHOLD) {
    return oo_alloc_large_mmap(n);
  }
  if (posix_memalign(&blk, OO_PAYLOAD_ALIGN, n) != 0) abort();
  pay = (char *)blk + OO_PAYLOAD_ALIGN;
  return pay;
}

void *oo_payload_alloc(size_t hdr_sz, size_t payload_sz) {
  void *pay = oo_payload_alloc_uninit(hdr_sz, payload_sz);
  if (pay) memset(pay, 0, payload_sz);
  return pay;
}

extern int oo_arena_free_payload(void *p);

/* A heap block's first 8 bytes can collide with OO_MMAP_MAGIC with p=2^-64.
 * Never trust the magic alone for munmap: the stored size must also be a
 * sane page-rounded mapping, or the block is treated as a posix payload. */
static int oo_mmap_size_ok(size_t map_sz) {
  if (map_sz < 4096 || map_sz > (size_t)(1LL << 32)) return 0;
  if (map_sz & 4095UL) return 0;
  return 1;
}

void oo_payload_free(void *payload) {
  if (!payload) return;
  if (oo_arena_free_payload(payload)) return;
  char *blk = (char *)payload - OO_PAYLOAD_ALIGN;
  if (blk == g_large_cached_blk || *(uint64_t *)blk == OO_MMAP_MAGIC) {
    if (blk == g_large_cached_blk) {
      g_large_cached_in_use = 0;
#if defined(__linux__)
      if (g_large_cached_sz > 4096) {
        madvise((char *)g_large_cached_blk + 4096, g_large_cached_sz - 4096, MADV_DONTNEED);
      }
#endif
      *(uint64_t *)g_large_cached_blk = OO_MMAP_MAGIC;
      *(size_t *)((char *)g_large_cached_blk + 8) = g_large_cached_sz;
      return;
    }
    size_t map_sz = *(size_t *)(blk + 8);
    if (oo_mmap_size_ok(map_sz)) {
      munmap(blk, map_sz);
      return;
    }
  }
  free(blk);
}

int oo_payload_aligned(const void *p) {
  if (!p) return 0;
  return (((uintptr_t)p) & (OO_PAYLOAD_ALIGN - 1)) == 0;
}

long long oo_list_block_bytes(long long cap, size_t elem) {
  if (cap <= 0) return 0;
  return (long long)OO_PAYLOAD_ALIGN + cap * (long long)elem;
}
