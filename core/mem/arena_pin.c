/* v2.3.0 split: CPU pinning for stable arena/dudect timing. Owns
 * oo_arena_pin_cpu which pins the calling thread to a core derived from
 * the OO_DUDECT_PIN env var (or 0). Uses pthread_setaffinity_np then
 * sched_setaffinity. Materializes the OO_LIST_AMBIENT_QUOTA env path
 * before pinning so the quota path is exercised under pin.
 * Orchestrator: arena.c. Sibling splits: arena_soa.c, arena_dod.c,
 * arena_checkpoint.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "../../oodar.h"
#include <pthread.h>
#include <stdlib.h>
#ifdef __linux__
#include <sched.h>
#include <unistd.h>
#endif

/* Materialize the ambient-quota env (declared in core/list/list.c) */
extern void oo_list_quota_init_public(void);

void oo_arena_pin_cpu(void) {
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
