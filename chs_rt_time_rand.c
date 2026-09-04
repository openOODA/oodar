/* M12: process-local TimeCap / RandCap — wall clock + entropy (not crypto object-caps) */
#include "chs_rt.h"
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

static pthread_once_t g_tr_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_prng_mu = PTHREAD_MUTEX_INITIALIZER;
static long long g_tok_time, g_tok_rand;
static unsigned long long g_prng = 1;

static void tr_once_init(void) {
  unsigned char b[16];
  size_t i;
  unsigned long long acc;
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(b, sizeof b) != 0)
#endif
  {
    acc = (unsigned long long)(uintptr_t)&g_tok_time;
    acc ^= (unsigned long long)getpid() << 16;
    acc ^= (unsigned long long)oo_monotonic_us();
    for (i = 0; i < sizeof b; i++) {
      acc = acc * 0x9E3779B97F4A7C15ULL + (unsigned long long)i;
      b[i] = (unsigned char)(acc >> 8);
    }
  }
  {
    unsigned long long ent0 = ((((unsigned long long)b[0]) << 56) |
                               (((unsigned long long)b[1]) << 48) |
                               (((unsigned long long)b[2]) << 40) |
                               (((unsigned long long)b[3]) << 32) |
                               (((unsigned long long)b[4]) << 24) |
                               (((unsigned long long)b[5]) << 16) |
                               (((unsigned long long)b[6]) << 8)  |
                               ((unsigned long long)b[7])) & 0x00FFFFFFFFFFFFFFULL;
    unsigned long long ent1 = ((((unsigned long long)b[8]) << 56)  |
                               (((unsigned long long)b[9]) << 48)  |
                               (((unsigned long long)b[10]) << 40) |
                               (((unsigned long long)b[11]) << 32) |
                               (((unsigned long long)b[12]) << 24) |
                               (((unsigned long long)b[13]) << 16) |
                               (((unsigned long long)b[14]) << 8)  |
                               ((unsigned long long)b[15])) & 0x00FFFFFFFFFFFFFFULL;
    g_tok_time = ((long long)(0x5 & 0x1F) << 56) | (long long)ent0;
    g_tok_rand = ((long long)(0x6 & 0x1F) << 56) | (long long)ent1;
  }
  if (g_tok_time == 0x4F4F544DLL) g_tok_time ^= 0x11111111LL;
  if (g_tok_rand == 0x4F4F524ELL) g_tok_rand ^= 0x11111111LL;
  pthread_mutex_lock(&g_prng_mu);
  g_prng = 1ULL | ((unsigned long long)b[8] << 8) | b[9];
  pthread_mutex_unlock(&g_prng_mu);
}

static void oo_tr_init(void) {
  pthread_once(&g_tr_once, tr_once_init);
}

long long oo_cap_grant_time(void) { oo_tr_init(); return g_tok_time; }
long long oo_cap_grant_rand(void) { oo_tr_init(); return g_tok_rand; }

void oo_cap_require_time(long long got, const char *op) {
  oo_tr_init();
  if (got != g_tok_time) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "time");
    exit(1);
  }
}
void oo_cap_require_rand(long long got, const char *op) {
  oo_tr_init();
  if (got != g_tok_rand) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "rand");
    exit(1);
  }
}

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

long long oo_random(long long cap) {
  unsigned char b[8];
  unsigned long long uv = 0;
  size_t i;
  oo_cap_require_rand(cap, "random");
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(b, sizeof b) == 0) {
    for (i = 0; i < 8; i++) uv = (uv << 8) | (unsigned long long)b[i];
    return (long long)uv;
  }
  /* Fail-closed: no LCG fallback. getentropy() must succeed for unpredictability. */
  fprintf(stderr, "ERR\tcap\trandom: getentropy() failed; refusing to derive unpredictability\n");
  return -1;
#else
  /* Fail-closed: no LCG fallback. getentropy() is required. */
  fprintf(stderr, "ERR\tcap\trandom: getentropy() not available; refusing to derive unpredictability\n");
  return -1;
#endif
}
