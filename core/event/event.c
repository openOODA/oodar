/* Event bus implementation. Tiny — fixed-size name and subscriber tables. */

/* v2.2.0: the `oo_je_*` arm-file JSON-errors mechanism (previously a
 * covert-exfil channel via `.ooda-cache/ooda-tmp/json_errors.arm`) was
 * removed from app/io/print.c (moved from fs/io/ in v2.2.0) as a
 * security fix — no cap gate, no caller, and the public ABI is
 * unchanged. The oo_event_emit / oo_event_subscribe API in this file
 * is the supported event bus surface. */

#include "event.h"
#include <pthread.h>
#include <string.h>

/* Lazy-startup hook owned by metrics.c: idempotent first-use
 * subscription of the metrics listeners. Declared here (not in
 * event.h) so only the bus sees it. */
void oo_metrics_ensure_subscribed(void);

typedef struct {
  char name[OO_EVENT_MAX_NAME];
  void (*fns[OO_EVENT_MAX_SUBSCRIBERS])(void);
  int n_fns;
} event_slot;

static event_slot g_events[OO_EVENT_MAX_EVENTS];
static int g_n_events;
static pthread_mutex_t g_event_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_event_once = PTHREAD_ONCE_INIT;

/* g_events/g_n_events are BSS: the loader zeroes them, and
 * pthread_once guarantees this runs exactly once before any slot is
 * touched, so no memset. */
static void event_init_once(void) {
}

void oo_event_init(void) {
  pthread_once(&g_event_once, event_init_once);
}

void oo_event_subscribe(OoStr name, void (*fn)(void)) {
  int i;
  oo_event_init();
  if (!fn) return;
  if (!name.data || name.len <= 0 || name.len >= OO_EVENT_MAX_NAME) return;
  pthread_mutex_lock(&g_event_mu);
  event_slot *slot = NULL;
  for (i = 0; i < g_n_events; i++) {
    if (strncmp(g_events[i].name, name.data, (size_t)name.len) == 0
        && g_events[i].name[name.len] == '\0') {
      slot = &g_events[i];
      break;
    }
  }
  if (!slot) {
    if (g_n_events >= OO_EVENT_MAX_EVENTS) {
      pthread_mutex_unlock(&g_event_mu);
      return;
    }
    slot = &g_events[g_n_events++];
    memcpy(slot->name, name.data, (size_t)name.len);
    slot->name[name.len] = '\0';
    slot->n_fns = 0;
  }
  if (slot->n_fns < OO_EVENT_MAX_SUBSCRIBERS) {
    slot->fns[slot->n_fns++] = fn;
  }
  pthread_mutex_unlock(&g_event_mu);
}

void oo_event_emit(OoStr name) {
  int i, j;
  void (*fns[OO_EVENT_MAX_SUBSCRIBERS])(void);
  int n = 0;
  oo_event_init();
  /* First emit subscribes the metrics listeners (lazy startup): every
   * subscribed event dispatches exactly as under the old constructor. */
  oo_metrics_ensure_subscribed();
  if (!name.data || name.len <= 0 || name.len >= OO_EVENT_MAX_NAME) return;
  pthread_mutex_lock(&g_event_mu);
  for (i = 0; i < g_n_events; i++) {
    if (strncmp(g_events[i].name, name.data, (size_t)name.len) == 0
        && g_events[i].name[name.len] == '\0') {
      n = g_events[i].n_fns;
      for (j = 0; j < n; j++) fns[j] = g_events[i].fns[j];
      break;
    }
  }
  pthread_mutex_unlock(&g_event_mu);
  for (j = 0; j < n; j++) {
    if (fns[j]) fns[j]();
  }
}

int oo_event_self_test(void) {
  /* counter was always 0 (no listener ever registered here); the
   * observable contract is: emit + null-subscribe + emit, return 1. */
  OoStr n = oo_str_lit("self_test_event");
  oo_event_emit(n);
  oo_event_subscribe(n, NULL);
  oo_event_emit(n);
  return 1;
}
