/* v2.3.0 split: orchestrator for the scoped bump arena. Owns the OoArena
 * type and the 32-slot g_ar[] table. arena_create / arena_alloc /
 * arena_reset / arena_destroy live here. SoA / DoD layout calculation in
 * arena_soa.c / arena_dod.c. Checkpoint / rollback + Welch double-run
 * determinism proof in arena_checkpoint.c. CPU pinning in arena_pin.c.
 * Ambient-quota fail-closed via g_quota_mu. Pure runtime/* only. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "../../oodar.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#define OO_ARENA_SLOTS 32

typedef struct {
  int live;
  char *base;
  size_t cap;
  size_t off;
  pthread_mutex_t mu;
  uint64_t gen;
} OoArena;

/* One slot in the live=0 / base=NULL / cap=off=0 / mutex=ready / gen=0
 * idle state. Used 32× to initialize g_ar[] below. */
#define OO_ARENA_SLOT_INIT {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0}
static OoArena g_ar[OO_ARENA_SLOTS] = {
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

/* Ambient quota state owned by core/list/list.c */
extern pthread_mutex_t g_quota_mu;
extern long long oo_list_ambient_quota;
extern long long oo_list_ambient_bytes;
extern void oo_arena_pin_cpu(void);

static int ar_alloc_slot(void) {
  int i;
  for (i = 0; i < OO_ARENA_SLOTS; i++) {
    if (!g_ar[i].live) return i;
  }
  return -1;
}

static void oo_arena_need(long long cap, const char *op) {
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
  if (bytes < 64 || bytes > (1LL << 28)) {
    r.val = oo_str_lit("arena_create: bad size");
    return r;
  }
  /* Hardening: pin CPU and enforce OO_LIST_AMBIENT_QUOTA */
  oo_arena_pin_cpu();
  oo_list_quota_init_public();
  pthread_mutex_lock(&g_quota_mu);
  if (oo_list_ambient_bytes + bytes > oo_list_ambient_quota) {
    pthread_mutex_unlock(&g_quota_mu);
    r.val = oo_str_lit("arena_create: ambient quota exceeded (AllocCap required, OO_LIST_AMBIENT_QUOTA)");
    return r;
  }
  oo_list_ambient_bytes += bytes;
  pthread_mutex_unlock(&g_quota_mu);

  mem = (char *)malloc((size_t)bytes);
  if (!mem) {
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= bytes;
    if (oo_list_ambient_bytes < 0) oo_list_ambient_bytes = 0;
    pthread_mutex_unlock(&g_quota_mu);
    r.val = oo_str_lit("arena_create: oom");
    return r;
  }
  pthread_mutex_lock(&g_ar_boot);
  s = ar_alloc_slot();
  if (s < 0) {
    pthread_mutex_unlock(&g_ar_boot);
    free(mem);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= bytes;
    if (oo_list_ambient_bytes < 0) oo_list_ambient_bytes = 0;
    pthread_mutex_unlock(&g_quota_mu);
    r.val = oo_str_lit("arena_create: no slot");
    return r;
  }
  pthread_mutex_lock(&g_ar[s].mu);
  g_ar[s].base = mem;
  g_ar[s].cap = (size_t)bytes;
  g_ar[s].off = 0;
  g_ar[s].live = 1;
  pthread_mutex_unlock(&g_ar[s].mu);
  pthread_mutex_unlock(&g_ar_boot);
  {
    char buf[32];
    snprintf(buf, sizeof buf, "arena:%d", s);
    r.ok = 1;
    r.val = oo_str_lit(buf);
  }
  return r;
}

OoResS oo_arena_alloc(long long cap, long long id, long long n) {
  OoResS r;
  int s = (int)id;
  OoArena *a;
  oo_arena_need(cap, "arena_alloc");
  r.ok = 0;
  r.val = oo_str_lit("arena_alloc failed");
  if (s < 0 || s >= OO_ARENA_SLOTS) {
    r.val = oo_str_lit("arena_alloc: bad id");
    return r;
  }
  if (n <= 0 || n > (1LL << 26)) {
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
  /* v2.1.0: reverse the comparison to prevent wrap.
   * Was: if (a->off + n > a->cap) — can wrap if a->off + n overflows size_t.
   * Now: if (n > a->cap - a->off) — the subtraction is exact on a valid arena. */
  if ((size_t)n > a->cap - a->off) {
    pthread_mutex_unlock(&a->mu);
    r.val = oo_str_lit("arena_alloc: full");
    return r;
  }
  {
    char buf[32];
    snprintf(buf, sizeof buf, "%llu", (unsigned long long)a->off);
    a->off += (size_t)n;
    pthread_mutex_unlock(&a->mu);
    r.ok = 1;
    r.val = oo_str_lit(buf);
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
  pthread_mutex_unlock(&a->mu);
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
  pthread_mutex_unlock(&a->mu);
  pthread_mutex_unlock(&g_ar_boot);
  if (to_free) {
    free(to_free);
    /* Release ambient quota */
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= (long long)freed_cap;
    if (oo_list_ambient_bytes < 0) oo_list_ambient_bytes = 0;
    pthread_mutex_unlock(&g_quota_mu);
  }
  r.ok = 1;
  r.val = oo_str_lit("OK");
  return r;
}
