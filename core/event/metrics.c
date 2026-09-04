/* Runtime metrics export (X4).
 *
 * Per-process counters for cap/PQC/AEAD/FS operations. Thread-safe via
 * pthread_mutex. Exposed to .oo via the C-ABI surface declared in oodar.h.
 *
 * Negative-trust contract (smoke_c_runtime_metrics.c):
 *   1. oo_metrics_incr(name) creates a counter that starts at 0; a second
 *      incr brings it to 2; a third brings it to 3 (deterministic).
 *   2. oo_metrics_get(name) returns the current value, never less than the
 *      last incr.
 *   3. oo_metrics_export() returns a valid JSON object containing at least
 *      one key per counter that has been touched.
 *   4. Names that look like JSON injection (quotes, braces) are rejected at
 *      the API boundary — they MUST NOT appear in the output.
 *   5. oo_metrics_self_test() returns 1 iff the module is consistent.
 *
 * Telemetry integration: this module subscribes to named events emitted by
 * the crypto and FS subsystems via the event bus. The producers no
 * longer call into metrics directly. Subscribed events:
 *   cap.seal, cap.attenuate, pq.sign, pq.verify, aead.seal, aead.open,
 *   fs.read, fs.write.
 */
#include "../../oodar.h"
#include "../../core/event/event.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define METRICS_MAX 64
#define METRICS_NAME_MAX 32

typedef struct {
  char name[METRICS_NAME_MAX];
  long long value;
  int in_use;
} metrics_slot;

static metrics_slot g_metrics[METRICS_MAX];
static pthread_once_t g_metrics_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_metrics_mu = PTHREAD_MUTEX_INITIALIZER;
/* v3.0.0: self-cap for the metrics module's internal callers (the
 * event-bus listeners at the bottom of this file). External callers
 * must obtain a MetricsCap via oo_cap_grant_metrics() and pass it as
 * the first arg. The internal cap is granted once at first use and
 * reused for all subsequent internal incr() calls. */
static long long g_metrics_self_cap = 0;

static void metrics_init_once(void) {
  memset(g_metrics, 0, sizeof g_metrics);
  g_metrics_self_cap = oo_cap_grant_metrics();
}

static void oo_metrics_init(void) {
  pthread_once(&g_metrics_once, metrics_init_once);
}

static int name_is_safe(const char *s, long long n) {
  if (!s || n <= 0 || n >= METRICS_NAME_MAX) return 0;
  for (long long i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '_' || c == '-') continue;
    return 0;
  }
  return 1;
}

static metrics_slot *find_slot_unlocked(const char *name, long long n, int create) {
  for (int i = 0; i < METRICS_MAX; i++) {
    if (g_metrics[i].in_use && strncmp(g_metrics[i].name, name, (size_t)n) == 0
        && g_metrics[i].name[n] == '\0') {
      return &g_metrics[i];
    }
  }
  if (!create) return 0;
  for (int i = 0; i < METRICS_MAX; i++) {
    if (!g_metrics[i].in_use) {
      g_metrics[i].in_use = 1;
      memcpy(g_metrics[i].name, name, (size_t)n);
      g_metrics[i].name[n] = '\0';
      g_metrics[i].value = 0;
      return &g_metrics[i];
    }
  }
  return 0;
}

int oo_metrics_incr(long long cap, OoStr name) {
  oo_cap_require_metrics(cap, "metrics_incr");
  if (!name_is_safe(name.data, name.len)) return 0;
  oo_metrics_init();
  pthread_mutex_lock(&g_metrics_mu);
  metrics_slot *s = find_slot_unlocked(name.data, name.len, 1);
  if (!s) {
    pthread_mutex_unlock(&g_metrics_mu);
    return 0;
  }
  s->value++;
  pthread_mutex_unlock(&g_metrics_mu);
  return 1;
}

long long oo_metrics_get(long long cap, OoStr name) {
  oo_cap_require_metrics(cap, "metrics_get");
  if (!name_is_safe(name.data, name.len)) return -1;
  oo_metrics_init();
  pthread_mutex_lock(&g_metrics_mu);
  metrics_slot *s = find_slot_unlocked(name.data, name.len, 0);
  long long val = s ? s->value : 0;
  pthread_mutex_unlock(&g_metrics_mu);
  return val;
}

int oo_metrics_reset(long long cap, OoStr name) {
  oo_cap_require_metrics(cap, "metrics_reset");
  if (!name_is_safe(name.data, name.len)) return 0;
  oo_metrics_init();
  pthread_mutex_lock(&g_metrics_mu);
  metrics_slot *s = find_slot_unlocked(name.data, name.len, 0);
  if (s) s->value = 0;
  pthread_mutex_unlock(&g_metrics_mu);
  return 1;
}

OoStr oo_metrics_export(long long cap) {
  oo_cap_require_metrics(cap, "metrics_export");
  oo_metrics_init();
  pthread_mutex_lock(&g_metrics_mu);
  /* Build a JSON object: {"counters":{name:value,...}} */
  /* First pass: total size. */
  size_t total = 16; /* {"counters":{}} + NUL headroom */
  for (int i = 0; i < METRICS_MAX; i++) {
    if (!g_metrics[i].in_use) continue;
    size_t nl = strlen(g_metrics[i].name);
    total += nl + 24; /* "name":value, */
  }
  char *buf = oo_str_alloc_payload(total);
  size_t off = 0;
  const char *prefix = "{\"counters\":{";
  memcpy(buf + off, prefix, strlen(prefix)); off += strlen(prefix);
  int first = 1;
  for (int i = 0; i < METRICS_MAX; i++) {
    if (!g_metrics[i].in_use) continue;
    if (!first) { buf[off++] = ','; }
    first = 0;
    size_t nl = strlen(g_metrics[i].name);
    buf[off++] = '"';
    memcpy(buf + off, g_metrics[i].name, nl); off += nl;
    buf[off++] = '"';
    buf[off++] = ':';
    /* Write the integer. */
    char numbuf[24];
    int nlen = snprintf(numbuf, sizeof numbuf, "%lld", g_metrics[i].value);
    if (nlen > 0) { memcpy(buf + off, numbuf, (size_t)nlen); off += (size_t)nlen; }
  }
  buf[off++] = '}';
  buf[off++] = '}';
  buf[off] = '\0';
  pthread_mutex_unlock(&g_metrics_mu);
  OoStr r; r.data = buf; r.len = (long long)off; return r;
}

int oo_metrics_self_test(long long cap) {
  /* v3.0.0: cap-gated. The self-test uses the caller's MetricsCap to
   * validate the module end-to-end. The internal event-bus listeners
   * use g_metrics_self_cap (granted at init). */
  oo_cap_require_metrics(cap, "metrics_self_test");
  /* incr + get round-trip. */
  OoStr nm = oo_str_lit("self_test_counter");
  oo_metrics_reset(cap, nm);
  long long v0 = oo_metrics_get(cap, nm);
  if (v0 != 0) return 0;
  oo_metrics_incr(cap, nm);
  oo_metrics_incr(cap, nm);
  oo_metrics_incr(cap, nm);
  long long v3 = oo_metrics_get(cap, nm);
  if (v3 != 3) return 0;
  /* Reject bad names. */
  OoStr bad = oo_str_lit("name with spaces");
  if (oo_metrics_incr(cap, bad) != 0) return 0;
  OoStr inj = oo_str_lit("name\"injection");
  if (oo_metrics_incr(cap, inj) != 0) return 0;
  /* Export is non-empty. */
  OoStr ex = oo_metrics_export(cap);
  int ok = (ex.data && ex.len > 0);
  if (ex.data) oo_str_release(ex);
  /* Cleanup. */
  oo_metrics_reset(cap, nm);
  return ok ? 1 : 0;
}

/* Event-listener functions invoked by the event bus when a producer emits
 * the corresponding named event. The producer no longer calls into metrics
 * directly; the event bus dispatches. v3.0.0: each listener forwards
 * g_metrics_self_cap (granted at metrics init) so the public
 * oo_metrics_incr() cap check is satisfied without an external caller. */
static void on_cap_attenuate(void) { OoStr n = oo_str_lit("cap_attenuate"); oo_metrics_incr(g_metrics_self_cap, n); }
static void on_pq_sign(void) { OoStr n = oo_str_lit("pq_sign"); oo_metrics_incr(g_metrics_self_cap, n); }
static void on_pq_verify(void) { OoStr n = oo_str_lit("pq_verify"); oo_metrics_incr(g_metrics_self_cap, n); }
static void on_aead_seal(void) { OoStr n = oo_str_lit("aead_seal"); oo_metrics_incr(g_metrics_self_cap, n); }
static void on_aead_open(void) { OoStr n = oo_str_lit("aead_open"); oo_metrics_incr(g_metrics_self_cap, n); }
/* v2.1.0: removed on_cap_seal, on_fs_read, on_fs_write (no emitters). */

static void metrics_subscribe_all(void) {
  /* v2.1.0: removed cap.seal, fs.read, fs.write subscriptions. They
   * were never emitted (no oo_event_emit call site in the umbrella).
   * Keep cap.attenuate (emitted in caps.c:154), pq.sign/verify and
   * aead.seal/open (emitted in pq_sig.c). */
  oo_event_subscribe(oo_str_lit("cap.attenuate"), on_cap_attenuate);
  oo_event_subscribe(oo_str_lit("pq.sign"), on_pq_sign);
  oo_event_subscribe(oo_str_lit("pq.verify"), on_pq_verify);
  oo_event_subscribe(oo_str_lit("aead.seal"), on_aead_seal);
  oo_event_subscribe(oo_str_lit("aead.open"), on_aead_open);
}

/* Constructor: subscribe at library load. GCC-specific; the runtime
 * umbrella is compiled with gcc per the oodar.c comment. */
__attribute__((constructor)) static void metrics_ctor(void) {
  metrics_subscribe_all();
}
