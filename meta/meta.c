/* Path-A metamorphic floor: process-local epoch + mix helpers for immune layouts.
 * Not runtime assembly mutation. Full DESIGN metamorphic product is residual. */
#include "../oodar.h"
#include <unistd.h>
#include <pthread.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

static pthread_once_t g_meta_once = PTHREAD_ONCE_INIT;
static long long g_meta_epoch;
static volatile long long g_meta_decoy_sink;

static void meta_once_init(void) {
  unsigned char b[8];
  size_t i;
  unsigned long long acc;
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(b, sizeof b) != 0) {
    /* Fail-closed: no LCG fallback. getentropy() must succeed for unpredictable epoch. */
    g_meta_epoch = -1;
    return;
  }
#else
  /* Fail-closed: no LCG fallback. getentropy() is required. */
  g_meta_epoch = -1;
  return;
#endif
  g_meta_epoch = (long long)((((unsigned long long)b[0]) << 56)
      | (((unsigned long long)b[1]) << 48)
      | (((unsigned long long)b[2]) << 40)
      | (((unsigned long long)b[3]) << 32)
      | (((unsigned long long)b[4]) << 24)
      | (((unsigned long long)b[5]) << 16)
      | (((unsigned long long)b[6]) << 8)
      | ((unsigned long long)b[7]));
  if (g_meta_epoch == 0) g_meta_epoch = 1;
}

static void oo_meta_init(void) {
  pthread_once(&g_meta_once, meta_once_init);
}

/* Process-local random epoch fixed at first call. Residual: not .text rewrite. */
long long oo_meta_epoch(void) {
  oo_meta_init();
  return g_meta_epoch;
}

/* Diversify seeds: epoch mixed with salt (not CSPRNG product claim). */
long long oo_meta_mix(long long salt) {
  unsigned long long x;
  oo_meta_init();
  x = (unsigned long long)g_meta_epoch ^ (unsigned long long)salt;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  x *= 0x9E3779B97F4A7C15ULL;
  return (long long)(x >> 1);
}

/* Advisory: OODA_METAMORPHIC=1 or OO_METAMORPHIC=1. Does not morph .text. */
int oo_meta_is_path_a(void) {
  const char *a = oo_process_policy_getenv("OODA_METAMORPHIC");
  const char *b = oo_process_policy_getenv("OO_METAMORPHIC");
  if (a && a[0] == '1' && a[1] == '\0') return 1;
  if (b && b[0] == '1' && b[1] == '\0') return 1;
  return 0;
}

/* Volatile sink so meta symbols stay live when only this is referenced. */
void oo_meta_decoy_touch(void) {
  oo_meta_init();
  g_meta_decoy_sink = g_meta_epoch;
  (void)g_meta_decoy_sink;
}
