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
int oo_arena_snap(int id, size_t *off, uint64_t *gen);
int oo_arena_restore(int id, size_t off, uint64_t gen);

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
