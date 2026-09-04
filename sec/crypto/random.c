/* sec/crypto/random.c — fail-closed getentropy-backed random source.
 *
 * v3.4.0 round-6: moved here from fs/os/time_rand.c per the misplaced-
 * files audit. The oo_random() function is crypto-grade (getentropy-
 * backed, no LCG fallback) and belongs in sec/crypto/, not fs/os/.
 *
 * The cap check (oo_cap_require_rand) now lives in sec/cap/cap_time.c
 * per the v3.4.0 split. */
#include "../../oodar.h"
#include <stddef.h>
#include <stdio.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

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
