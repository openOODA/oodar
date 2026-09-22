/* v2.3.0 split + v3.1.0 audit cleanup: arena checkpoint / rollback stack.
 * Owns the g_ck[] stack and g_ck_mu mutex. Checkpoint pushes v and
 * returns the new stack depth (0..OO_CK_MAX-1), or -1 if full. Rollback
 * pops and returns the top value, or 0 if empty. Both are gated by ArenaCap
 * (v3.0.0 Floor; AllocCap is no longer sufficient at the checkpoint site).
 *
 * v3.1.0 audit removed:
 *   - oo_arena_welch_t (the Welch t-test, dead — never called)
 *   - oo_arena_double_run_proof (the `__attribute__((unused))` dead helper
 *     with stub inputs that always passed). The arena-determinism proof
 *     lives in qa/dudect_c_native.c; this duplicate was dead.
 * The qa/ test is the canonical place for the Welch test. */
#include "../../oodar.h"
#include <pthread.h>

#define OO_CK_MAX 8
typedef struct { int id; size_t off; uint64_t gen; } OoCk;
static OoCk g_ck[OO_CK_MAX];
static int g_ck_n;
static pthread_mutex_t g_ck_mu = PTHREAD_MUTEX_INITIALIZER;

#ifndef OO_ARENA_SLOTS
#define OO_ARENA_SLOTS 32
#endif
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
extern OoArena g_ar[OO_ARENA_SLOTS];

int oo_arena_snap(int id, size_t *off, uint64_t *gen) {
  OoArena *a;
  if (id < 0 || id >= OO_ARENA_SLOTS || !off || !gen) return 0;
  a = &g_ar[id];
  pthread_mutex_lock(&a->mu);
  if (!a->live) { pthread_mutex_unlock(&a->mu); return 0; }
  *off = a->off;
  *gen = a->gen;
  pthread_mutex_unlock(&a->mu);
  return 1;
}

/* Frame stack owned by oo_arena_alloc_payload / oo_arena_free_payload below.
 * Every touch holds the slot mutex. Declared here so restore can prune. */
#define OO_ARENA_STACK_MAX 256
typedef struct {
  void *pay;
  size_t cur;
  size_t end;
  int dead;
} OoArenaFrame;

static OoArenaFrame s_ar_stack[OO_ARENA_SLOTS][OO_ARENA_STACK_MAX];
static int s_ar_stack_top[OO_ARENA_SLOTS];

int oo_arena_restore(int id, size_t off, uint64_t gen) {
  OoArena *a;
  if (id < 0 || id >= OO_ARENA_SLOTS) return 0;
  a = &g_ar[id];
  pthread_mutex_lock(&a->mu);
  if (!a->live || a->gen != gen || off > a->cap) {
    pthread_mutex_unlock(&a->mu);
    return 0;
  }
  a->off = off;
  /* Prune post-snapshot frames (cur >= off) so a later free cannot rewind
   * off below live data. Frames spanning off (cur < off) stay. */
  {
    int top = s_ar_stack_top[id];
    while (top > 0 && s_ar_stack[id][top - 1].cur >= off) top--;
    s_ar_stack_top[id] = top;
  }
  pthread_mutex_unlock(&a->mu);
  return 1;
}

long long oo_checkpoint(long long cap, long long v) {
  size_t off = 0;
  uint64_t gen = 0;
  long long ret = -1;
  oo_cap_require_arena(cap, "checkpoint");
  if (!oo_arena_snap((int)v, &off, &gen)) return -1;
  pthread_mutex_lock(&g_ck_mu);
  if (g_ck_n < OO_CK_MAX) {
    g_ck[g_ck_n].id = (int)v;
    g_ck[g_ck_n].off = off;
    g_ck[g_ck_n].gen = gen;
    ret = (long long)g_ck_n++;
  }
  pthread_mutex_unlock(&g_ck_mu);
  return ret;
}

long long oo_rollback(long long cap) {
  OoCk ck;
  long long ret = 0;
  oo_cap_require_arena(cap, "rollback");
  pthread_mutex_lock(&g_ck_mu);
  if (g_ck_n <= 0) {
    pthread_mutex_unlock(&g_ck_mu);
    return 0;
  }
  ck = g_ck[--g_ck_n];
  pthread_mutex_unlock(&g_ck_mu);
  if (!oo_arena_restore(ck.id, ck.off, ck.gen)) return 0;
  ret = (long long)ck.id;
  return ret;
}

static __thread int g_active_arena_slot = -1;

int oo_arena_active_id(void) {
  return g_active_arena_slot;
}

extern void oo_arena_need(long long cap, const char *op);

OoResS oo_arena_attach(long long cap, long long id) {
  OoResS r;
  int s = (int)id;
  int ok = 0;
  oo_arena_need(cap, "arena_attach");
  if (s >= 0 && s < OO_ARENA_SLOTS) {
    pthread_mutex_lock(&g_ar[s].mu);
    ok = g_ar[s].live;
    pthread_mutex_unlock(&g_ar[s].mu);
  }
  if (ok) g_active_arena_slot = s;
  r.ok = ok;
  r.val = oo_str_lit(ok ? "OK" : "arena_attach failed");
  return r;
}

OoResS oo_arena_detach(long long cap) {
  OoResS r;
  oo_arena_need(cap, "arena_detach");
  g_active_arena_slot = -1;
  r.ok = 1;
  r.val = oo_str_lit("OK");
  return r;
}

void *oo_arena_alloc_payload(int slot, size_t hdr_sz, size_t payload_sz) {
  OoArena *a;
  size_t hsz, cur, end_off;
  uintptr_t base_addr;
  if (slot < 0 || slot >= OO_ARENA_SLOTS || payload_sz > (1ULL << 30)) return NULL;
  a = &g_ar[slot];
  /* All in-tree hdr sizes (OoStrHeader/OoListHeader=8, OoFlatEnvHeader=16)
   * are already 8-aligned; the mask only rounds hypothetical odd sizes. */
  hsz = (hdr_sz + 7) & ~(size_t)7;

  pthread_mutex_lock(&a->mu);
  if (!a->live || !a->base) {
    pthread_mutex_unlock(&a->mu);
    return NULL;
  }
  /* Full frame stack: fail closed BEFORE bumping off (callers fall back
   * to heap). Wrapping to 0 would drop live frames and leak until reset. */
  if (s_ar_stack_top[slot] >= OO_ARENA_STACK_MAX) {
    pthread_mutex_unlock(&a->mu);
    return NULL;
  }
  base_addr = (uintptr_t)a->base;
  cur = (a->off + 7) & ~(size_t)7;
  end_off = cur + hsz + payload_sz;
  if (end_off > a->cap) {
    pthread_mutex_unlock(&a->mu);
    return NULL;
  }
  char *pay = (char *)(base_addr + cur + hsz);
  memset((char *)(base_addr + cur), 0, hsz);
  size_t new_off = (end_off + 7) & ~(size_t)7;
  int top = s_ar_stack_top[slot];
  a->off = new_off;
  s_ar_stack[slot][top].pay = pay;
  s_ar_stack[slot][top].cur = cur;
  s_ar_stack[slot][top].end = new_off;
  s_ar_stack[slot][top].dead = 0;
  s_ar_stack_top[slot] = top + 1;
  pthread_mutex_unlock(&a->mu);
  return pay;
}

/* Slot range test: one unsigned compare. Dead slots have base==NULL and
 * cap==0, so addr-NULL >= 0 rejects them with no extra branch; a below-base
 * addr wraps huge (user VA < 2^52, cap <= 2^30) and is likewise rejected.
 * Single-pass under the slot mutex: check and act share the lock, so a
 * racing reset/destroy cannot slip between them (no TOCTOU, no recheck). */
int oo_arena_free_payload(void *p) {
  if (!p) return 0;
  uintptr_t addr = (uintptr_t)p;
  for (int i = 0; i < OO_ARENA_SLOTS; i++) {
    OoArena *a = &g_ar[i];
    int top, k;
    pthread_mutex_lock(&a->mu);
    if (addr - (uintptr_t)a->base >= a->cap) {
      pthread_mutex_unlock(&a->mu);
      continue;
    }
    top = s_ar_stack_top[i];
    for (k = top - 1; k >= 0; k--) {
      if (s_ar_stack[i][k].pay == p) { s_ar_stack[i][k].dead = 1; break; }
    }
    while (top > 0 && s_ar_stack[i][top - 1].dead) {
      if (s_ar_stack[i][top - 1].end == a->off) a->off = s_ar_stack[i][top - 1].cur;
      top--;
    }
    s_ar_stack_top[i] = top;
    pthread_mutex_unlock(&a->mu);
    return 1;
  }
  return 0;
}

/* Read-only membership: same one-compare range test, no frame mutation
 * (the old body delegated to free, marking frames dead on a mere query). */
int oo_arena_contains_ptr(const void *p) {
  if (!p) return 0;
  uintptr_t addr = (uintptr_t)p;
  for (int i = 0; i < OO_ARENA_SLOTS; i++) {
    OoArena *a = &g_ar[i];
    int hit;
    pthread_mutex_lock(&a->mu);
    hit = (addr - (uintptr_t)a->base < a->cap);
    pthread_mutex_unlock(&a->mu);
    if (hit) return 1;
  }
  return 0;
}

void oo_arena_on_destroy(int slot) {
  if (slot >= 0 && slot < OO_ARENA_SLOTS) s_ar_stack_top[slot] = 0;
  if (g_active_arena_slot == slot) g_active_arena_slot = -1;
}

