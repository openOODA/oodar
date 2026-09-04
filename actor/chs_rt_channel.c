/* M164: process-local message channels under ThreadCap (path A).
 * Bounded string queues: 16 slots × 8 messages; mutex + condvar.
 * Not multi-process, not actor model, not DESIGN fearless concurrency. */
#include "chs_rt.h"
#include <pthread.h>

#define OO_CH_SLOTS 16
#define OO_CH_QDEPTH 8

typedef struct {
  int live;
  int head;
  int tail;
  int count;
  OoStr msgs[OO_CH_QDEPTH];
  pthread_mutex_t mu;
  pthread_cond_t not_empty;
  pthread_cond_t not_full;
} OoChannel;

static OoChannel g_chs[OO_CH_SLOTS];
static pthread_mutex_t g_ch_boot = PTHREAD_MUTEX_INITIALIZER;

static OoStr oo_ch_copy(OoStr s) {
  OoStr r;
  long long n;
  if (!s.data || s.len <= 0) {
    return oo_str_lit("");
  }
  n = s.len;
  if (n > (1LL << 20)) n = 1LL << 20;
  r.len = n;
  r.data = oo_str_alloc_payload((size_t)n);
  memcpy(r.data, s.data, (size_t)n);
  return r;
}

static int ch_alloc_slot(void) {
  int i;
  for (i = 0; i < OO_CH_SLOTS; i++) {
    if (!g_chs[i].live) return i;
  }
  return -1;
}

OoResS oo_channel_new(long long cap) {
  OoResS r;
  int slot;
  char buf[32];
  oo_cap_require_thread(cap, "channel_new");
  pthread_mutex_lock(&g_ch_boot);
  slot = ch_alloc_slot();
  if (slot < 0) {
    pthread_mutex_unlock(&g_ch_boot);
    r.ok = 0;
    r.val = oo_str_lit("channel_new: no free slot");
    return r;
  }
  g_chs[slot].live = 1;
  g_chs[slot].head = 0;
  g_chs[slot].tail = 0;
  g_chs[slot].count = 0;
  pthread_mutex_init(&g_chs[slot].mu, NULL);
  pthread_cond_init(&g_chs[slot].not_empty, NULL);
  pthread_cond_init(&g_chs[slot].not_full, NULL);
  pthread_mutex_unlock(&g_ch_boot);
  snprintf(buf, sizeof buf, "ch:%d", slot);
  r.ok = 1;
  r.val = oo_str_lit(buf);
  return r;
}

OoResS oo_channel_send(long long cap, long long slot, OoStr msg) {
  OoResS r;
  int s = (int)slot;
  OoChannel *ch;
  oo_cap_require_thread(cap, "channel_send");
  if (s < 0 || s >= OO_CH_SLOTS) {
    r.ok = 0;
    r.val = oo_str_lit("channel_send: bad slot");
    return r;
  }
  ch = &g_chs[s];
  if (!ch->live) {
    r.ok = 0;
    r.val = oo_str_lit("channel_send: empty slot");
    return r;
  }
  pthread_mutex_lock(&ch->mu);
  if (ch->count >= OO_CH_QDEPTH) {
    pthread_mutex_unlock(&ch->mu);
    r.ok = 0;
    r.val = oo_str_lit("channel_send: full");
    return r;
  }
  ch->msgs[ch->tail] = oo_ch_copy(msg);
  ch->tail = (ch->tail + 1) % OO_CH_QDEPTH;
  ch->count++;
  pthread_cond_signal(&ch->not_empty);
  pthread_mutex_unlock(&ch->mu);
  r.ok = 1;
  r.val = oo_str_lit("sent");
  return r;
}

OoResS oo_channel_destroy(long long cap, long long slot) {
  OoResS r;
  int s = (int)slot;
  OoChannel *ch;
  oo_cap_require_thread(cap, "channel_destroy");
  if (s < 0 || s >= OO_CH_SLOTS) {
    r.ok = 0; r.val = oo_str_lit("channel_destroy: bad slot"); return r;
  }
  pthread_mutex_lock(&g_ch_boot);
  ch = &g_chs[s];
  if (!ch->live) {
    pthread_mutex_unlock(&g_ch_boot);
    r.ok = 0; r.val = oo_str_lit("channel_destroy: empty slot"); return r;
  }
  pthread_mutex_lock(&ch->mu);
  while (ch->count > 0) {
    OoStr m = ch->msgs[ch->head];
    if (m.data) oo_str_release(m);
    ch->head = (ch->head + 1) % OO_CH_QDEPTH;
    ch->count--;
  }
  ch->head = 0; ch->tail = 0;
  ch->live = 0;
  pthread_mutex_unlock(&ch->mu);
  pthread_mutex_destroy(&ch->mu);
  pthread_cond_destroy(&ch->not_empty);
  pthread_cond_destroy(&ch->not_full);
  pthread_mutex_unlock(&g_ch_boot);
  r.ok = 1; r.val = oo_str_lit("destroyed");
  return r;
}

/* Non-blocking recv: Ok(msg) or Err empty (path A; no timeout product). */
OoResS oo_channel_recv(long long cap, long long slot) {
  OoResS r;
  int s = (int)slot;
  OoChannel *ch;
  oo_cap_require_thread(cap, "channel_recv");
  if (s < 0 || s >= OO_CH_SLOTS) {
    r.ok = 0;
    r.val = oo_str_lit("channel_recv: bad slot");
    return r;
  }
  ch = &g_chs[s];
  if (!ch->live) {
    r.ok = 0;
    r.val = oo_str_lit("channel_recv: empty slot");
    return r;
  }
  pthread_mutex_lock(&ch->mu);
  if (ch->count <= 0) {
    pthread_mutex_unlock(&ch->mu);
    r.ok = 0;
    r.val = oo_str_lit("channel_recv: empty");
    return r;
  }
  r.ok = 1;
  r.val = ch->msgs[ch->head];
  ch->head = (ch->head + 1) % OO_CH_QDEPTH;
  ch->count--;
  pthread_cond_signal(&ch->not_full);
  pthread_mutex_unlock(&ch->mu);
  return r;
}
