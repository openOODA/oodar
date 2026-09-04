/* M12: process-local TimeCap time helpers.
 *
 * v3.4.0 round-6: the cap subsystem (TimeCap / RandCap grant/require)
 * moved to sec/cap/cap_time.c; oo_random() moved to sec/crypto/random.c.
 * This file is now the TimeCap-requiring time helpers only.
 *
 * Not OS rlimit / heap isolation / ASAN. Wall-clock only. */
#include "../../oodar.h"
#include <time.h>

long long oo_now_ms(long long cap) {
  struct timespec ts;
  oo_cap_require_time(cap, "now_ms");
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
  return (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
}

void oo_sleep_ms(long long cap, long long ms) {
  struct timespec ts;
  oo_cap_require_time(cap, "sleep_ms");
  if (ms < 0) ms = 0;
  ts.tv_sec = (time_t)(ms / 1000);
  ts.tv_nsec = (long)((ms % 1000) * 1000000L);
  nanosleep(&ts, NULL);
}
