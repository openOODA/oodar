/* v2.3.0 split + v3.1.0 audit cleanup: arena checkpoint / rollback stack.
 * Owns the g_ck[] stack and g_ck_mu mutex. Checkpoint pushes v and
 * returns the new stack depth (0..OO_CK_MAX-1), or -1 if full. Rollback
 * pops and returns the top value, or 0 if empty. Both are gated by ArenaCap.
 * Payload frames are tracked via embedded OoArenaBlockHdr at the start of
 * each 64-byte aligned arena block. Pure runtime only. */
#include "../../oodar.h"
#include <pthread.h>

#define OO_CK_MAX 8
typedef struct { int id; size_t off; uint64_t gen; size_t top_cur; } OoCk;
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
  size_t top_cur;
} OoArena;
#endif
extern OoArena g_ar[OO_ARENA_SLOTS];

int oo_arena_snap(int id, size_t *off, uint64_t *gen, size_t *top_cur) {
  OoArena *a;
  if (id < 0 || id >= OO_ARENA_SLOTS || !off || !gen || !top_cur) return 0;
  a = &g_ar[id];
  pthread_mutex_lock(&a->mu);
  if (!a->live) { pthread_mutex_unlock(&a->mu); return 0; }
  *off = a->off;
  *gen = a->gen;
  *top_cur = a->top_cur;
  pthread_mutex_unlock(&a->mu);
  return 1;
}

int oo_arena_restore(int id, size_t off, uint64_t gen, size_t top_cur) {
  OoArena *a;
  if (id < 0 || id >= OO_ARENA_SLOTS) return 0;
  a = &g_ar[id];
  pthread_mutex_lock(&a->mu);
  if (!a->live || a->gen != gen || off > a->cap) {
    pthread_mutex_unlock(&a->mu);
    return 0;
  }
  a->off = off;
  a->top_cur = top_cur;
  pthread_mutex_unlock(&a->mu);
  return 1;
}

long long oo_checkpoint(long long cap, long long v) {
  size_t off = 0;
  uint64_t gen = 0;
  size_t top_cur = (size_t)-1;
  long long ret = -1;
  oo_cap_require_arena(cap, "checkpoint");
  if (!oo_arena_snap((int)v, &off, &gen, &top_cur)) return -1;
  pthread_mutex_lock(&g_ck_mu);
  if (g_ck_n < OO_CK_MAX) {
    g_ck[g_ck_n].id = (int)v;
    g_ck[g_ck_n].off = off;
    g_ck[g_ck_n].gen = gen;
    g_ck[g_ck_n].top_cur = top_cur;
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
  if (!oo_arena_restore(ck.id, ck.off, ck.gen, ck.top_cur)) return 0;
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

#define OO_ARENA_BLOCK_MAGIC 0x4F4F4152454E4131ULL /* "OOARENA1" */

typedef struct OoArenaBlockHdr {
  size_t cur;
  size_t prev;
  size_t end;
  uint32_t dead;
  uint32_t magic;
} OoArenaBlockHdr;

void *oo_arena_alloc_payload(int slot, size_t hdr_sz, size_t payload_sz) {
  OoArena *a;
  size_t cur, end_off;
  uintptr_t base_addr;
  if (slot < 0 || slot >= OO_ARENA_SLOTS || payload_sz > (1ULL << 30)) return NULL;
  a = &g_ar[slot];
  (void)hdr_sz;

  pthread_mutex_lock(&a->mu);
  if (!a->live || !a->base) {
    pthread_mutex_unlock(&a->mu);
    return NULL;
  }
  base_addr = (uintptr_t)a->base;
  cur = (a->off + 63) & ~63ULL;
  end_off = cur + 64 + payload_sz;
  if (end_off > a->cap) {
    pthread_mutex_unlock(&a->mu);
    return NULL;
  }
  char *blk = (char *)(base_addr + cur);
  char *pay = blk + 64;
  memset(blk, 0, 64);

  OoArenaBlockHdr *hdr = (OoArenaBlockHdr *)blk;
  hdr->cur = cur;
  hdr->prev = a->top_cur;
  hdr->end = end_off;
  hdr->dead = 0;
  hdr->magic = (uint32_t)OO_ARENA_BLOCK_MAGIC;

  a->off = (end_off + 63) & ~63ULL;
  a->top_cur = cur;
  pthread_mutex_unlock(&a->mu);
  return pay;
}

int oo_arena_free_payload(void *p) {
  if (!p) return 0;
  uintptr_t addr = (uintptr_t)p;
  for (int i = 0; i < OO_ARENA_SLOTS; i++) {
    OoArena *a = &g_ar[i];
    pthread_mutex_lock(&a->mu);
    if (!a->live || !a->base || addr - (uintptr_t)a->base >= a->cap) {
      pthread_mutex_unlock(&a->mu);
      continue;
    }
    char *blk = (char *)p - 64;
    OoArenaBlockHdr *hdr = (OoArenaBlockHdr *)blk;
    if (hdr->magic != (uint32_t)OO_ARENA_BLOCK_MAGIC) {
      pthread_mutex_unlock(&a->mu);
      return 0;
    }
    hdr->dead = 1;
    while (a->top_cur != (size_t)-1) {
      OoArenaBlockHdr *top_hdr = (OoArenaBlockHdr *)((char *)a->base + a->top_cur);
      if (!top_hdr->dead) break;
      a->off = top_hdr->cur;
      a->top_cur = top_hdr->prev;
    }
    pthread_mutex_unlock(&a->mu);
    return 1;
  }
  return 0;
}

int oo_arena_contains_ptr(const void *p) {
  if (!p) return 0;
  uintptr_t addr = (uintptr_t)p;
  for (int i = 0; i < OO_ARENA_SLOTS; i++) {
    OoArena *a = &g_ar[i];
    int hit;
    pthread_mutex_lock(&a->mu);
    hit = (a->live && a->base && addr - (uintptr_t)a->base < a->cap);
    pthread_mutex_unlock(&a->mu);
    if (hit) return 1;
  }
  return 0;
}

void oo_arena_on_destroy(int slot) {
  if (slot >= 0 && slot < OO_ARENA_SLOTS) {
    g_ar[slot].top_cur = (size_t)-1;
  }
  if (g_active_arena_slot == slot) g_active_arena_slot = -1;
}
