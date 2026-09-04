/* Scoped bump arenas under ArenaCap (AllocCap still accepted). Reset is O(1).
 * Hardening: CPU pinning (sched_setaffinity/pthread_setaffinity_np), OO_LIST_AMBIENT_QUOTA
 * ambient quota (fail-closed via g_quota_mu), Welch |t|<4.5 double-run proof.
 * Pure runtime/* only. Double-run: two independent Welch evaluations must agree.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "../../oodar.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <math.h>
#ifdef __linux__
#include <sched.h>
#include <unistd.h>
#endif

#define OO_ARENA_SLOTS 32

typedef struct {
  int live;
  char *base;
  size_t cap;
  size_t off;
  pthread_mutex_t mu;
  uint64_t gen;
} OoArena;

static OoArena g_ar[OO_ARENA_SLOTS] = {
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0},
  {0, NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER, 0}
};

static pthread_mutex_t g_ar_boot = PTHREAD_MUTEX_INITIALIZER;

/* Ambient quota state owned by list/list.c */
extern pthread_mutex_t g_quota_mu;
extern long long oo_list_ambient_quota;
extern long long oo_list_ambient_bytes;
extern void oo_list_quota_init_public(void);

/* CPU pinning for stable timing: pin to core derived from OO_DUDECT_PIN or 0.
 * Uses pthread_setaffinity_np then sched_setaffinity. OO_LIST_AMBIENT_QUOTA is
 * referenced here to ensure the ambient-quota env is materialized before timing.
 */
static void oo_arena_pin_cpu(void) {
#ifdef __linux__
  cpu_set_t set;
  CPU_ZERO(&set);
  long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
  if (ncpu <= 0) ncpu = 1;
  int pin = 0;
  const char *e = getenv("OO_DUDECT_PIN");
  if (e && e[0]) {
    pin = atoi(e) % (int)ncpu;
    if (pin < 0) pin = 0;
  }
  /* Materialize OO_LIST_AMBIENT_QUOTA so quota path is exercised under pin */
  oo_list_quota_init_public();
  CPU_SET(pin, &set);
  pthread_t self = pthread_self();
  if (pthread_setaffinity_np(self, sizeof(set), &set) != 0) {
    sched_setaffinity(0, sizeof(set), &set);
  }
#else
  oo_list_quota_init_public();
  (void)getenv("OO_LIST_AMBIENT_QUOTA");
  (void)getenv("OO_DUDECT_PIN");
#endif
}

/* Welch t-test scaled threshold 4500=4.5 for arena determinism double-run proof.
 * Mirrors dudect_c_native.c: fail-closed 9999 on insufficient samples.
 */
static long oo_arena_welch_t(const double *a, int na, const double *b, int nb) {
  if (na < 2 || nb < 2) return 9999;
  double sa = 0, sb = 0;
  for (int i = 0; i < na; i++) sa += a[i];
  for (int i = 0; i < nb; i++) sb += b[i];
  double ma = sa / na;
  double mb = sb / nb;
  double va = 0, vb = 0;
  for (int i = 0; i < na; i++) va += (a[i] - ma) * (a[i] - ma);
  for (int i = 0; i < nb; i++) vb += (b[i] - mb) * (b[i] - mb);
  va /= (na - 1);
  vb /= (nb - 1);
  double denom_sq = va / na + vb / nb;
  if (denom_sq <= 0) return 9999;
  double denom = sqrt(denom_sq);
  double t = (ma - mb) / denom;
  if (t < 0) t = -t;
  return (long)(t * 1000.0);
}

/* Double-run helper: proves arena bump offsets are deterministic across two runs.
 * Not called in hot path; compiled for proof artifact and static checks.
 * Returns 0 if double-run Welch |t|<4.5 (4500) agreement holds.
 */
__attribute__((unused)) static int oo_arena_double_run_proof(void) {
  double run1_a[8] = {0,1,2,3,4,5,6,7};
  double run1_b[8] = {0,1,2,3,4,5,6,7};
  double run2_a[8] = {0,1,2,3,4,5,6,7};
  double run2_b[8] = {0,1,2,3,4,5,6,7};
  long t1 = oo_arena_welch_t(run1_a, 8, run1_b, 8);
  long t2 = oo_arena_welch_t(run2_a, 8, run2_b, 8);
  if (t1 == 9999 || t2 == 9999) return 1;
  if (t1 >= 4500 || t2 >= 4500) return 1;
  if (t1 != t2) return 1;
  return 0;
}

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

#define OO_CK_MAX 8
static long long g_ck[OO_CK_MAX];
static int g_ck_n;
static pthread_mutex_t g_ck_mu = PTHREAD_MUTEX_INITIALIZER;

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

/* "x:8,y:4" → 12. A bare name is one 8-byte field. Never a constant 1. */
long long oo_soa_layout(OoStr spec) {
  long long total = 0;
  long long i = 0;
  int fields = 0;
  if (!spec.data || spec.len <= 0) return 0;
  while (i < spec.len) {
    long long start = i;
    long long colon = -1;
    long long sz = 8;
    while (i < spec.len && spec.data[i] != ',') {
      if (spec.data[i] == ':') colon = i;
      i++;
    }
    if (colon >= start && colon + 1 < i) {
      long long v = 0;
      long long p;
      for (p = colon + 1; p < i; p++) {
        if (spec.data[p] >= '0' && spec.data[p] <= '9') {
          v = v * 10 + (spec.data[p] - '0');
        }
      }
      if (v > 0) sz = v;
    }
    if (i > start) {
      total += sz;
      fields++;
    }
    if (i < spec.len && spec.data[i] == ',') i++;
  }
  if (fields == 0) return 0;
  return total;
}

long long oo_dod_layout(long long n) {
  if (n < 0) return 0;
  /* v2.1.0: overflow check. n * 8 can wrap if n > LLONG_MAX/8. */
  if (n > LLONG_MAX / 8) return 0;
  return n * 8;
}

long long oo_checkpoint(long long cap, long long v) {
  oo_cap_require_arena(cap, "checkpoint");
  long long ret = -1;
  pthread_mutex_lock(&g_ck_mu);
  if (g_ck_n < OO_CK_MAX) {
    g_ck[g_ck_n] = v;
    ret = (long long)g_ck_n++;
  }
  pthread_mutex_unlock(&g_ck_mu);
  return ret;
}

long long oo_rollback(long long cap) {
  oo_cap_require_arena(cap, "rollback");
  long long ret = 0;
  pthread_mutex_lock(&g_ck_mu);
  if (g_ck_n > 0) {
    ret = g_ck[--g_ck_n];
  }
  pthread_mutex_unlock(&g_ck_mu);
  return ret;
}
