/* sec/cap/cap_ffi.c — FFICap subsystem (grant / require).
 *
 * v3.4.0 round-6: moved here from app/xlang/ffi_sec.c per the
 * misplaced-files audit. The cap store, init, and the oo_cap_grant_ffi /
 * oo_cap_require_ffi functions belong with the rest of the cap module —
 * app/xlang/ffi_sec.c just calls oo_cap_require_ffi().
 *
 * The fail-closed getentropy pattern (no LCG fallback) matches the
 * canonical store in sec/cap/caps.c. */
#include "../../oodar.h"
#include <pthread.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

static pthread_once_t g_ffi_once = PTHREAD_ONCE_INIT;
/* v3.4.1: keep g_tok_ffi static. See cap_alloc.c for the reason. */
static long long g_tok_ffi;
static void ffi_zeroize(void);

static void ffi_once_init(void) {
  unsigned char b[8];
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(b, sizeof b) != 0) {
    /* Fail-closed: no LCG fallback. getentropy() must succeed for unpredictable FFI token. */
    fprintf(stderr, "ERR\tcap\tgetentropy() failed; refusing to derive FFI capability token\n");
    abort();
  }
#else
  /* Fail-closed: no LCG fallback. getentropy() is required. */
  fprintf(stderr, "ERR\tcap\tgetentropy() not available; refusing to derive FFI capability token\n");
  abort();
#endif
  /* v2.2.0: removed the hardcoded 0x5 "ffi band" in the high byte.
   * The canonical cap system (sec/cap/caps.c, make_cap_tok) does not
   * use a band byte at all — the comment there calls the band byte
   * "redundant and ... consuming entropy" — so the FFI token now uses
   * the full 8 bytes of getentropy randomness, matching the caps.c
   * layout. The cap is identified by which g_tok_ffi global it
   * is stored in, not by a tag in the high byte. */
  {
    unsigned long long ent = ((((unsigned long long)b[0]) << 56) |
                              (((unsigned long long)b[1]) << 48) |
                              (((unsigned long long)b[2]) << 40) |
                              (((unsigned long long)b[3]) << 32) |
                              (((unsigned long long)b[4]) << 24) |
                              (((unsigned long long)b[5]) << 16) |
                              (((unsigned long long)b[6]) << 8)  |
                              ((unsigned long long)b[7]));
    g_tok_ffi = (long long)ent;
  }
  if (g_tok_ffi == 0x4F4F4649LL) g_tok_ffi ^= 0x11111111LL;
  if (g_tok_ffi == 0) g_tok_ffi = 1;
  if (atexit(ffi_zeroize) != 0) abort();
}

static void ffi_zeroize(void) {
  explicit_bzero(&g_tok_ffi, sizeof g_tok_ffi);
}

static void oo_ffi_init(void) {
  pthread_once(&g_ffi_once, ffi_once_init);
}

long long oo_cap_grant_ffi(void) {
  oo_ffi_init();
  return g_tok_ffi;
}

void oo_cap_require_ffi(long long got, const char *op) {
  oo_ffi_init();
  if (got == 0 || got != g_tok_ffi) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n",
            op ? op : "ffi");
    exit(1);
  }
}
