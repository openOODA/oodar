/* M165 path A: thin actors under ThreadCap with OS worker threads.
 * actor_spawn → joinable pthread worker + private mailbox channel; Ok("actor:N").
 * actor_send / actor_recv are mutex/condvar-synchronized mailbox wrappers. */
#include "../oodar.h"
#include <pthread.h>
#include <stdint.h>

#define OO_ACTOR_SLOTS 16
#define OO_ACTOR_QDEPTH 8

typedef struct {
  int live, running, stop_req;
  pthread_t thr;
  int head, tail, count;
  OoStr msgs[OO_ACTOR_QDEPTH];
  pthread_mutex_t mu;
  pthread_cond_t cond, not_full;
  uint64_t msgs_processed;
  char name[32];
} OoActor;

static OoActor g_actors[OO_ACTOR_SLOTS];
static pthread_mutex_t g_act_boot = PTHREAD_MUTEX_INITIALIZER;

static void *oo_actor_worker_loop(void *arg) {
  int slot = (int)(intptr_t)arg;
  OoActor *a;
  if (slot < 0 || slot >= OO_ACTOR_SLOTS) return NULL;
  a = &g_actors[slot];
  pthread_mutex_lock(&a->mu);
  a->running = 1;
  while (!a->stop_req && a->live) {
    if (a->count == 0) { pthread_cond_wait(&a->cond, &a->mu); continue; }
    a->msgs_processed++;
    pthread_cond_wait(&a->cond, &a->mu);
  }
  a->running = 0;
  pthread_mutex_unlock(&a->mu);
  return NULL;
}

static OoStr oo_act_copy(OoStr s) {
  OoStr r;
  long long n;
  if (!s.data || s.len <= 0) return oo_str_lit("");
  n = s.len > (1LL << 20) ? (1LL << 20) : s.len;
  r.len = n;
  r.data = oo_str_alloc_payload((size_t)n);
  memcpy(r.data, s.data, (size_t)n);
  return r;
}

static int act_alloc_slot(void) {
  for (int i = 0; i < OO_ACTOR_SLOTS; i++) {
    if (!g_actors[i].live) return i;
  }
  return -1;
}

OoResS oo_actor_spawn(long long cap, OoStr name) {
  OoResS r;
  int slot;
  char buf[32];
  oo_cap_require_thread(cap, "actor_spawn");
  pthread_mutex_lock(&g_act_boot);
  slot = act_alloc_slot();
  if (slot < 0) {
    pthread_mutex_unlock(&g_act_boot);
    r.ok = 0; r.val = oo_str_lit("actor_spawn: no free slot"); return r;
  }
  OoActor *a = &g_actors[slot];
  a->live = 1; a->running = 0; a->stop_req = 0;
  a->head = 0; a->tail = 0; a->count = 0; a->msgs_processed = 0;
  if (name.data && name.len > 0) {
    size_t clen = (size_t)(name.len < 31 ? name.len : 31);
    memcpy(a->name, name.data, clen);
    a->name[clen] = '\0';
  } else { a->name[0] = '\0'; }
  pthread_mutex_init(&a->mu, NULL);
  pthread_cond_init(&a->cond, NULL);
  pthread_cond_init(&a->not_full, NULL);
  if (pthread_create(&a->thr, NULL, oo_actor_worker_loop, (void *)(intptr_t)slot) != 0) {
    a->live = 0;
    pthread_mutex_destroy(&a->mu);
    pthread_cond_destroy(&a->cond);
    pthread_cond_destroy(&a->not_full);
    pthread_mutex_unlock(&g_act_boot);
    r.ok = 0; r.val = oo_str_lit("actor_spawn failed"); return r;
  }
  pthread_mutex_unlock(&g_act_boot);
  snprintf(buf, sizeof buf, "actor:%d", slot);
  r.ok = 1; r.val = oo_str_lit(buf); return r;
}

OoResS oo_actor_send(long long cap, long long id, OoStr msg) {
  OoResS r;
  int s = (int)id;
  OoActor *a;
  oo_cap_require_thread(cap, "actor_send");
  if (s < 0 || s >= OO_ACTOR_SLOTS) {
    r.ok = 0; r.val = oo_str_lit("actor_send: bad id"); return r;
  }
  a = &g_actors[s];
  if (!a->live) { r.ok = 0; r.val = oo_str_lit("actor_send: empty slot"); return r; }
  pthread_mutex_lock(&a->mu);
  if (a->count >= OO_ACTOR_QDEPTH) {
    pthread_mutex_unlock(&a->mu);
    r.ok = 0; r.val = oo_str_lit("actor_send: full"); return r;
  }
  a->msgs[a->tail] = oo_act_copy(msg);
  a->tail = (a->tail + 1) % OO_ACTOR_QDEPTH;
  a->count++;
  pthread_cond_signal(&a->cond);
  pthread_mutex_unlock(&a->mu);
  r.ok = 1; r.val = oo_str_lit("sent"); return r;
}

/* Non-blocking recv: Ok(msg) or Err empty (path A). */
OoResS oo_actor_recv(long long cap, long long id) {
  OoResS r;
  int s = (int)id;
  OoActor *a;
  oo_cap_require_thread(cap, "actor_recv");
  if (s < 0 || s >= OO_ACTOR_SLOTS) {
    r.ok = 0; r.val = oo_str_lit("actor_recv: bad id"); return r;
  }
  a = &g_actors[s];
  if (!a->live) { r.ok = 0; r.val = oo_str_lit("actor_recv: empty slot"); return r; }
  pthread_mutex_lock(&a->mu);
  if (a->count <= 0) {
    pthread_mutex_unlock(&a->mu);
    r.ok = 0; r.val = oo_str_lit("actor_recv: empty"); return r;
  }
  r.ok = 1;
  r.val = a->msgs[a->head];
  a->head = (a->head + 1) % OO_ACTOR_QDEPTH;
  a->count--;
  pthread_cond_signal(&a->not_full);
  pthread_mutex_unlock(&a->mu);
  return r;
}

OoResS oo_actor_destroy(long long cap, long long id) {
  OoResS r;
  int s = (int)id;
  OoActor *a;
  oo_cap_require_thread(cap, "actor_destroy");
  if (s < 0 || s >= OO_ACTOR_SLOTS) {
    r.ok = 0; r.val = oo_str_lit("actor_destroy: bad id"); return r;
  }
  pthread_mutex_lock(&g_act_boot);
  a = &g_actors[s];
  if (!a->live) {
    pthread_mutex_unlock(&g_act_boot);
    r.ok = 0; r.val = oo_str_lit("actor_destroy: empty slot"); return r;
  }
  pthread_mutex_lock(&a->mu);
  a->stop_req = 1;
  pthread_cond_broadcast(&a->cond);
  pthread_mutex_unlock(&a->mu);
  /* Hold g_act_boot until pthread_join + destroy complete, so a concurrent
   * spawn cannot reuse this slot and observe a half-destroyed mutex/cond. */
  pthread_join(a->thr, NULL);
  pthread_mutex_lock(&a->mu);
  while (a->count > 0) {
    OoStr m = a->msgs[a->head];
    if (m.data) oo_str_release(m);
    a->head = (a->head + 1) % OO_ACTOR_QDEPTH;
    a->count--;
  }
  a->live = 0; a->running = 0; a->stop_req = 0;
  a->head = 0; a->tail = 0; a->msgs_processed = 0;
  pthread_mutex_unlock(&a->mu);
  pthread_mutex_destroy(&a->mu);
  pthread_cond_destroy(&a->cond);
  pthread_cond_destroy(&a->not_full);
  pthread_mutex_unlock(&g_act_boot);
  r.ok = 1; r.val = oo_str_lit("destroyed");
  return r;
}

/* OTP floor: join the active worker thread and spawn a fresh one. Mailbox stays. */
OoResS oo_actor_restart(long long cap, long long id) {
  OoResS r;
  int s = (int)id;
  OoActor *a;
  oo_cap_require_thread(cap, "actor_restart");
  r.ok = 0; r.val = oo_str_lit("actor_restart failed");
  if (s < 0 || s >= OO_ACTOR_SLOTS) {
    r.val = oo_str_lit("actor_restart: bad id"); return r;
  }
  a = &g_actors[s];
  pthread_mutex_lock(&g_act_boot);
  if (!a->live) {
    pthread_mutex_unlock(&g_act_boot);
    r.val = oo_str_lit("actor_restart: empty slot"); return r;
  }
  pthread_mutex_lock(&a->mu);
  a->stop_req = 1;
  pthread_cond_broadcast(&a->cond);
  pthread_mutex_unlock(&a->mu);

  /* Hold g_act_boot across the join so concurrent callers cannot observe
   * a transient dead slot between join and pthread_create. */
  pthread_join(a->thr, NULL);

  pthread_mutex_lock(&a->mu);
  a->stop_req = 0; a->running = 1;
  pthread_mutex_unlock(&a->mu);

  if (pthread_create(&a->thr, NULL, oo_actor_worker_loop, (void *)(intptr_t)s) != 0) {
    a->live = 0;
    pthread_mutex_unlock(&g_act_boot);
    r.val = oo_str_lit("actor_restart: spawn failed"); return r;
  }
  pthread_mutex_unlock(&g_act_boot);
  r.ok = 1; r.val = oo_str_lit("restarted"); return r;
}

static unsigned char g_otp_once[OO_ACTOR_SLOTS];

OoResS oo_otp_supervise(long long cap, long long id) {
  OoResS r;
  int s = (int)id;
  oo_cap_require_thread(cap, "otp_supervise");
  r.ok = 0; r.val = oo_str_lit("otp_supervise: bad id");
  if (s < 0 || s >= OO_ACTOR_SLOTS) return r;
  if (g_otp_once[s]) { r.val = oo_str_lit("otp_supervise: already"); return r; }
  if (!g_actors[s].live) { r.val = oo_str_lit("otp_supervise: empty"); return r; }
  g_otp_once[s] = 1;
  return oo_actor_restart(cap, id);
}

static OoStr oo_rpc_mac(long long cap, OoStr payload) {
  char key[32];
  snprintf(key, sizeof key, "%llx", (unsigned long long)cap);
  return crypto_hmac_sha256_internal(oo_str_lit(key), payload);
}

OoResS oo_cap_rpc_send(long long cap, OoStr payload) {
  OoResS r;
  OoStr mac;
  char *out;
  oo_cap_require_thread(cap, "cap_rpc_send");
  r.ok = 0; r.val = oo_str_lit("cap_rpc_send: bad payload");
  if (payload.len < 0 || payload.len > 192) return r;
  mac = oo_rpc_mac(cap, payload);
  if (!mac.data || mac.len != 64) {
    if (mac.data) oo_str_release(mac);
    return r;
  }
  out = oo_str_alloc_payload((size_t)(64 + payload.len));
  memcpy(out, mac.data, 64);
  oo_str_release(mac);
  if (payload.len > 0 && payload.data)
    memcpy(out + 64, payload.data, (size_t)payload.len);
  r.ok = 1; r.val.data = out; r.val.len = 64 + payload.len;
  return r;
}

OoResS oo_cap_rpc_recv(long long cap, OoStr sealed) {
  OoResS r;
  OoStr pay, mac;
  char *out;
  oo_cap_require_thread(cap, "cap_rpc_recv");
  r.ok = 0; r.val = oo_str_lit("cap_rpc_recv: hmac");
  if (!sealed.data || sealed.len < 64) return r;
  pay.data = sealed.data + 64; pay.len = sealed.len - 64;
  mac = oo_rpc_mac(cap, pay);
  if (mac.len != 64 || crypto_ct_cmp(mac.data, sealed.data, 64) != 0) {
    if (mac.data) oo_str_release(mac);
    return r;
  }
  oo_str_release(mac);
  out = oo_str_alloc_payload((size_t)pay.len);
  if (pay.len > 0) memcpy(out, pay.data, (size_t)pay.len);
  r.ok = 1; r.val.data = out; r.val.len = pay.len;
  return r;
}
