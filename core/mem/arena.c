/* v2.3.0 split: orchestrator for the scoped bump arena. Owns the OoArena
 * type and the 32-slot g_ar[] table. arena_create / arena_alloc /
 * arena_reset / arena_destroy live here. SoA / DoD layout calculation in
 * arena_soa.c / arena_dod.c. Checkpoint / rollback + attach/detach + the
 * payload frame stack in arena_checkpoint.c. CPU pinning in arena_pin.c.
 * Backed by anonymous mmap (munmap on destroy, MADVISE on reset); arena
 * memory sits outside the ambient list quota by design (pass-scoped scratch
 * would otherwise trip the 64MB default). Pure runtime only. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "../../oodar.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#if defined(__linux__)
#include <malloc.h>
#include <sys/mman.h>
#endif

#define OO_ARENA_SLOTS 32

#ifndef OO_ARENA_TYPE_DEFINED
#define OO_ARENA_TYPE_DEFINED 1
typedef struct OoArena {
  int live;
  char *base;
  size_t cap;
  size_t off;
  pthread_mutex_t mu;
  uint64_t gen;
} OoArena;
#endif

/* One slot in the live=0 / base=NULL / cap=off=0 / mutex=ready / gen=0
 * idle state. Used 32× to initialize g_ar[] below. */
#define OO_ARENA_SLOT_INIT {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0}
OoArena g_ar[OO_ARENA_SLOTS] = {
  OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT,
  OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT,
  OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT,
  OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT,
  OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT,
  OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT,
  OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT,
  OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT, OO_ARENA_SLOT_INIT
};
#undef OO_ARENA_SLOT_INIT

static pthread_mutex_t g_ar_boot = PTHREAD_MUTEX_INITIALIZER;

/* Static id strings: oo_str_lit interns into static storage, so returning
 * these keeps create's result valid past return (a stack snprintf buf would
 * dangle). File scope: mid-function static definitions break some tooling. */
static const char *s_arena_names[OO_ARENA_SLOTS] = {
  "0", "1", "2", "3", "4", "5", "6", "7",
  "8", "9", "10", "11", "12", "13", "14", "15",
  "16", "17", "18", "19", "20", "21", "22", "23",
  "24", "25", "26", "27", "28", "29", "30", "31"
};

extern void oo_arena_pin_cpu(void);

static int ar_alloc_slot(void) {
  int i;
  for (i = 0; i < OO_ARENA_SLOTS; i++) {
    if (!g_ar[i].live) return i;
  }
  return -1;
}

void oo_arena_need(long long cap, const char *op) {
  if (oo_cap_is_arena(cap) || oo_cap_is_alloc(cap)) return;
  fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "arena");
  exit(1);
}

OoResS oo_arena_create(long long cap, long long bytes) {
  OoResS r;
  int s;
  char *mem;
  oo_arena_need(cap, "arena_create");
  r.ok = 0;
  r.val = oo_str_lit("arena_create failed");
  if (bytes < 64 || bytes > (1LL << 30)) {
    r.val = oo_str_lit("arena_create: bad size");
    return r;
  }
  /* Hardening: pin CPU */
  oo_arena_pin_cpu();

  size_t alloc_cap = (size_t)bytes;
  size_t map_sz = (alloc_cap + 4095) & ~4095UL;
  mem = (char *)mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    r.val = oo_str_lit("arena_create: oom");
    return r;
  }
  pthread_mutex_lock(&g_ar_boot);
  s = ar_alloc_slot();
  if (s < 0) {
    pthread_mutex_unlock(&g_ar_boot);
    munmap(mem, map_sz);
    r.val = oo_str_lit("arena_create: no slot");
    return r;
  }
  pthread_mutex_lock(&g_ar[s].mu);
  g_ar[s].base = mem;
  g_ar[s].cap = alloc_cap;
  g_ar[s].off = 0;
  g_ar[s].live = 1;
  g_ar[s].gen++;
  pthread_mutex_unlock(&g_ar[s].mu);
  pthread_mutex_unlock(&g_ar_boot);
  r.ok = 1;
  r.val = oo_str_lit(s_arena_names[s]);
  return r;
}
extern OoResS oo_arena_attach(long long cap, long long id);
extern OoResS oo_arena_detach(long long cap);

OoResS oo_arena_alloc(long long cap, long long id, long long n) {
  OoResS r;
  int s = (int)id;
  OoArena *a;
  oo_arena_need(cap, "arena_alloc");
  if (n == 0) return oo_arena_attach(cap, id);
  if (n < 0) return oo_arena_detach(cap);
  r.ok = 0;
  r.val = oo_str_lit("arena_alloc failed");
  if (s < 0 || s >= OO_ARENA_SLOTS) {
    r.val = oo_str_lit("arena_alloc: bad id");
    return r;
  }
  if (n > (1LL << 26)) {
    r.val = oo_str_lit("arena_alloc: bad n");
    return r;
  }
  a = &g_ar[s];
  pthread_mutex_lock(&a->mu);
  if (!a->live) {
    pthread_mutex_unlock(&a->mu);
    r.val = oo_str_lit("arena_alloc: bad id");
    return r;
  }
  if (a->off & 15) a->off = (a->off + 15) & ~15ULL;
  if ((size_t)n > a->cap - a->off) {
    pthread_mutex_unlock(&a->mu);
    r.val = oo_str_lit("arena_alloc: full");
    return r;
  }
  {
    unsigned long long allocated_off = (unsigned long long)a->off;
    a->off += (size_t)n;
    pthread_mutex_unlock(&a->mu);
    r.ok = 1;
    r.val = oo_int_to_str((long long)allocated_off);
  }
  return r;
}

OoResS oo_arena_reset(long long cap, long long id) {
  OoResS r;
  int s = (int)id;
  OoArena *a;
  oo_arena_need(cap, "arena_reset");
  r.ok = 0;
  r.val = oo_str_lit("arena_reset failed");
  if (s < 0 || s >= OO_ARENA_SLOTS) {
    r.val = oo_str_lit("arena_reset: bad id");
    return r;
  }
  a = &g_ar[s];
  pthread_mutex_lock(&a->mu);
  if (!a->live) {
    pthread_mutex_unlock(&a->mu);
    r.val = oo_str_lit("arena_reset: bad id");
    return r;
  }
  a->off = 0;
  extern void oo_arena_on_destroy(int slot);
  oo_arena_on_destroy(s);
  char *base = a->base;
  size_t acap = a->cap;
  pthread_mutex_unlock(&a->mu);
#if defined(__linux__)
  /* Release backing pages; the heap is the allocator's business, not the
   * arena's (a trim here would tax every compiler pass reset). */
  if (base && acap > 0) madvise(base, (acap + 4095) & ~4095UL, MADV_DONTNEED);
#endif
  r.ok = 1;
  r.val = oo_str_lit("OK");
  return r;
}

OoResS oo_arena_destroy(long long cap, long long id) {
  OoResS r;
  int s = (int)id;
  OoArena *a;
  char *to_free = NULL;
  size_t freed_cap = 0;
  oo_arena_need(cap, "arena_destroy");
  r.ok = 0;
  r.val = oo_str_lit("arena_destroy failed");
  if (s < 0 || s >= OO_ARENA_SLOTS) {
    r.val = oo_str_lit("arena_destroy: bad id");
    return r;
  }
  pthread_mutex_lock(&g_ar_boot);
  a = &g_ar[s];
  pthread_mutex_lock(&a->mu);
  if (!a->live) {
    pthread_mutex_unlock(&a->mu);
    pthread_mutex_unlock(&g_ar_boot);
    r.val = oo_str_lit("arena_destroy: bad id");
    return r;
  }
  to_free = a->base;
  freed_cap = a->cap;
  a->base = NULL;
  a->live = 0;
  a->cap = 0;
  a->off = 0;
  {
    extern void oo_arena_on_destroy(int slot);
    oo_arena_on_destroy(s);
  }
  pthread_mutex_unlock(&a->mu);
  pthread_mutex_unlock(&g_ar_boot);
  if (to_free) {
    munmap(to_free, (freed_cap + 4095) & ~4095UL);
  }
  r.ok = 1;
  r.val = oo_str_lit("OK");
  return r;
}

OoResS oo_arena_pass_reset(long long cap, long long id) {
  return oo_arena_reset(cap, id);
}
