/* M163: joinable pthread path A under ThreadCap (slot table, not detach). */
#include "../../oodar.h"
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>

#define OO_THREAD_SLOTS 64

typedef struct {
  pthread_t thr;
  int live;           /* 1 = joinable live slot */
  int running;        /* 1 = OS worker thread active */
  int stop_req;       /* 1 = stop requested */
  pthread_mutex_t mu; /* slot-level mutex */
  pthread_cond_t cond;/* worker condition variable */
  char name[32];      /* worker thread name */
} OoThreadSlot;

static OoThreadSlot g_threads[OO_THREAD_SLOTS];
static pthread_mutex_t g_thr_boot = PTHREAD_MUTEX_INITIALIZER;

static void *oo_thread_worker(void *arg) {
  int slot = (int)(intptr_t)arg;
  if (slot < 0 || slot >= OO_THREAD_SLOTS) return NULL;
  OoThreadSlot *s = &g_threads[slot];

  pthread_mutex_lock(&s->mu);
  s->running = 1;
  while (!s->stop_req && s->live) {
    pthread_cond_wait(&s->cond, &s->mu);
  }
  s->running = 0;
  pthread_mutex_unlock(&s->mu);
  return NULL;
}

static int thr_alloc_slot(void) {
  int i;
  for (i = 0; i < OO_THREAD_SLOTS; i++) {
    if (!g_threads[i].live) return i;
  }
  return -1;
}

/* Parse "tid:N" → slot, or -1 on failure. */
static long long thr_parse_tid(OoStr s) {
  long long n = 0;
  long long i;
  if (!s.data || s.len < 5) return -1;
  if (s.data[0] != 't' || s.data[1] != 'i' || s.data[2] != 'd' || s.data[3] != ':')
    return -1;
  if (s.len == 4) return -1;
  for (i = 4; i < s.len; i++) {
    char c = s.data[i];
    if (c < '0' || c > '9') return -1;
    n = n * 10 + (long long)(c - '0');
    if (n >= OO_THREAD_SLOTS) return -1;
  }
  return n;
}

OoResS oo_thread_spawn(long long cap, OoStr name) {
  OoResS r;
  int slot;
  char buf[32];
  oo_cap_require_thread(cap, "thread_spawn");
  pthread_mutex_lock(&g_thr_boot);
  slot = thr_alloc_slot();
  if (slot < 0) {
    pthread_mutex_unlock(&g_thr_boot);
    r.ok = 0;
    r.val = oo_str_lit("thread_spawn: no free slot");
    return r;
  }
  OoThreadSlot *ts = &g_threads[slot];
  ts->live = 1;
  ts->running = 0;
  ts->stop_req = 0;
  if (name.data && name.len > 0) {
    size_t copy_len = (size_t)(name.len < 31 ? name.len : 31);
    memcpy(ts->name, name.data, copy_len);
    ts->name[copy_len] = '\0';
  } else {
    ts->name[0] = '\0';
  }
  pthread_mutex_init(&ts->mu, NULL);
  pthread_cond_init(&ts->cond, NULL);

  if (pthread_create(&ts->thr, NULL, oo_thread_worker, (void *)(intptr_t)slot) != 0) {
    ts->live = 0;
    pthread_mutex_destroy(&ts->mu);
    pthread_cond_destroy(&ts->cond);
    pthread_mutex_unlock(&g_thr_boot);
    r.ok = 0;
    r.val = oo_str_lit("thread_spawn failed");
    return r;
  }
  pthread_mutex_unlock(&g_thr_boot);
  snprintf(buf, sizeof buf, "tid:%d", slot);
  r.ok = 1;
  r.val = oo_str_lit(buf);
  return r;
}

/* Preferred: join by Int slot index. */
OoResS oo_thread_join(long long cap, long long slot) {
  OoResS r;
  int s = (int)slot;
  pthread_t th;
  oo_cap_require_thread(cap, "thread_join");
  if (s < 0 || s >= OO_THREAD_SLOTS) {
    r.ok = 0;
    r.val = oo_str_lit("thread_join: bad slot");
    return r;
  }
  pthread_mutex_lock(&g_thr_boot);
  OoThreadSlot *ts = &g_threads[s];
  if (!ts->live) {
    pthread_mutex_unlock(&g_thr_boot);
    r.ok = 0;
    r.val = oo_str_lit("thread_join: empty slot");
    return r;
  }
  th = ts->thr;
  pthread_mutex_lock(&ts->mu);
  ts->stop_req = 1;
  pthread_cond_broadcast(&ts->cond);
  pthread_mutex_unlock(&ts->mu);

  ts->live = 0;
  /* Hold g_thr_boot until pthread_join + destroy complete, so another
   * spawn cannot reuse this slot and observe a half-destroyed mutex/cond. */
  if (pthread_join(th, NULL) != 0) {
    pthread_mutex_unlock(&g_thr_boot);
    r.ok = 0;
    r.val = oo_str_lit("thread_join failed");
    return r;
  }
  pthread_mutex_destroy(&ts->mu);
  pthread_cond_destroy(&ts->cond);
  pthread_mutex_unlock(&g_thr_boot);

  r.ok = 1;
  r.val = oo_str_lit("joined");
  return r;
}

/* Join by String "tid:N" (parse → slot). */
OoResS oo_thread_join_s(long long cap, OoStr tid) {
  long long slot = thr_parse_tid(tid);
  OoResS r;
  if (slot < 0) {
    oo_cap_require_thread(cap, "thread_join");
    r.ok = 0;
    r.val = oo_str_lit("thread_join: bad tid");
    return r;
  }
  /* cap is checked again inside oo_thread_join; do not skip the check. */
  return oo_thread_join(cap, slot);
}
