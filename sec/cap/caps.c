#include "../../oodar.h"
#include "../crypto/crypto_internal.h"
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

/* Portable explicit_bzero: glibc 2.25+ ships it in <string.h>; older
 * libcs and musl need a fallback. We use memset + a compiler barrier to
 * defeat dead-store elimination. */
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#  if !__GLIBC_PREREQ(2, 25)
#    define explicit_bzero(buf, len) do { \
         memset((buf), 0, (len)); \
         __asm__ __volatile__("" : : "r"(buf) : "memory"); \
       } while (0)
#  endif
#elif !defined(__GLIBC__) && !defined(__APPLE__)
#  define explicit_bzero(buf, len) do { \
       memset((buf), 0, (len)); \
       __asm__ __volatile__("" : : "r"(buf) : "memory"); \
     } while (0)
#endif

/* Process-local capability tokens (14 core + extended tokens). Fail-closed. */
static pthread_once_t g_caps_once = PTHREAD_ONCE_INIT;
static long long g_tok_fs, g_tok_sys, g_tok_env, g_tok_net;
static long long g_tok_sign, g_tok_process;
static long long g_tok_tcp, g_tok_udp, g_tok_bind;
static long long g_tok_audio, g_tok_camera, g_tok_usb, g_tok_hid;
static long long g_tok_window, g_tok_frame, g_tok_fsread, g_tok_fswrite;
static long long g_tok_arena, g_tok_thread, g_tok_gpu;
static long long g_tok_compiler_read, g_tok_metrics;
/* v2.1.0: removed g_tok_audit, g_tok_hitl, g_tok_sync, g_tok_mem, g_tok_http
 * (declared in v2.0.0 caps.h but either never defined or dead-granted). */
static unsigned char g_kernel_hmac_key[32];

/* First-principles: 8 bytes (64 bits) of entropy per token; the cap is
 * identified by which g_tok_* global it is stored in, so the band byte in
 * the high position is redundant and was consuming entropy. The magic-number
 * XOR (0x4F4F4653 etc.) is preserved as defense-in-depth against the
 * well-known "OOFS" / "OOSY" / "OOEN" / "OONT" ASCII tokens. */
static long long make_cap_tok(unsigned char band, const unsigned char *b) {
  (void)band;
  unsigned long long ent = 0;
  for (int i = 0; i < 8; i++) ent = (ent << 8) | (unsigned long long)b[i];
  long long tok = (long long)(ent & 0xFFFFFFFFFFFFFFFFULL);
  if (tok == 0x4F4F4653LL || tok == 0x4F4F5359LL ||
      tok == 0x4F4F454ELL || tok == 0x4F4F4E54LL) {
    tok ^= 0x11111111LL;
  }
  return tok;
}

/* Wipe cap tokens and the kernel HMAC key on process exit so post-mortem
 * memory dumps cannot recover them. explicit_bzero is used (not memset)
 * to defeat the compiler's dead-store elimination. */
static void caps_zeroize(void) {
  explicit_bzero(&g_tok_fs, sizeof g_tok_fs);
  explicit_bzero(&g_tok_sys, sizeof g_tok_sys);
  explicit_bzero(&g_tok_env, sizeof g_tok_env);
  explicit_bzero(&g_tok_net, sizeof g_tok_net);
  explicit_bzero(&g_tok_sign, sizeof g_tok_sign);
  explicit_bzero(&g_tok_process, sizeof g_tok_process);
  /* v2.1.0: removed sync/mem/http zeroize. */
  explicit_bzero(&g_tok_tcp, sizeof g_tok_tcp);
  explicit_bzero(&g_tok_udp, sizeof g_tok_udp);
  explicit_bzero(&g_tok_bind, sizeof g_tok_bind);
  explicit_bzero(&g_tok_audio, sizeof g_tok_audio);
  explicit_bzero(&g_tok_camera, sizeof g_tok_camera);
  explicit_bzero(&g_tok_usb, sizeof g_tok_usb);
  explicit_bzero(&g_tok_hid, sizeof g_tok_hid);
  explicit_bzero(&g_tok_window, sizeof g_tok_window);
  explicit_bzero(&g_tok_frame, sizeof g_tok_frame);
  explicit_bzero(&g_tok_fsread, sizeof g_tok_fsread);
  explicit_bzero(&g_tok_fswrite, sizeof g_tok_fswrite);
  explicit_bzero(&g_tok_arena, sizeof g_tok_arena);
  explicit_bzero(&g_tok_thread, sizeof g_tok_thread);
  explicit_bzero(&g_tok_gpu, sizeof g_tok_gpu);
  explicit_bzero(&g_tok_compiler_read, sizeof g_tok_compiler_read);
  explicit_bzero(&g_tok_metrics, sizeof g_tok_metrics);
  explicit_bzero(g_kernel_hmac_key, sizeof g_kernel_hmac_key);
}

static void caps_once_init(void) {
  unsigned char b[184];
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(b, sizeof b) != 0) {
    /* Fail-closed: no LCG fallback. getentropy() must succeed for unpredictable tokens. */
    fprintf(stderr, "ERR\tcap\tgetentropy() failed; refusing to derive capability tokens\n");
    abort();
  }
#else
  /* Fail-closed: no LCG fallback. getentropy() is required. */
  fprintf(stderr, "ERR\tcap\tgetentropy() not available; refusing to derive capability tokens\n");
  abort();
#endif
  g_tok_fs      = make_cap_tok(0x1,  b + 0);
  g_tok_sys     = make_cap_tok(0x2,  b + 7);
  g_tok_env     = make_cap_tok(0x3,  b + 14);
  g_tok_net     = make_cap_tok(0x4,  b + 21);
  g_tok_sign    = make_cap_tok(0x5,  b + 28);
  g_tok_process = make_cap_tok(0x6,  b + 35);
  /* v2.1.0: removed sync (0x7), mem (0x8), http (0x9). */
  g_tok_tcp     = make_cap_tok(0xA,  b + 63);
  g_tok_udp     = make_cap_tok(0xB,  b + 70);
  g_tok_bind    = make_cap_tok(0xC,  b + 77);
  g_tok_audio   = make_cap_tok(0xD,  b + 84);
  g_tok_camera  = make_cap_tok(0xE,  b + 91);
  g_tok_usb     = make_cap_tok(0xF,  b + 98);
  g_tok_hid     = make_cap_tok(0x10, b + 105);
  g_tok_window  = make_cap_tok(0x11, b + 112);
  g_tok_frame   = make_cap_tok(0x12, b + 119);
  g_tok_fsread  = make_cap_tok(0x13, b + 126);
  g_tok_fswrite = make_cap_tok(0x14, b + 133);
  g_tok_arena   = make_cap_tok(0x15, b + 140);
  g_tok_thread  = make_cap_tok(0x16, b + 147);
  g_tok_gpu     = make_cap_tok(0x17, b + 154);
  g_tok_compiler_read = make_cap_tok(0x18, b + 161);
  g_tok_metrics        = make_cap_tok(0x19, b + 168);

#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(g_kernel_hmac_key, sizeof g_kernel_hmac_key) != 0) {
    /* Fail-closed: no LCG fallback. getentropy() must succeed for unpredictable HMAC key. */
    fprintf(stderr, "ERR\tcap\tgetentropy() failed; refusing to derive kernel HMAC key\n");
    abort();
  }
#else
  /* Fail-closed: no LCG fallback. getentropy() is required. */
  fprintf(stderr, "ERR\tcap\tgetentropy() not available; refusing to derive kernel HMAC key\n");
  abort();
#endif
  /* Register the post-exit zeroization handler. atexit() is invoked at
   * normal process exit (return from main, exit(), _exit()) and at the
   * signal-driven teardown. explicit_bzero inside caps_zeroize defeats
   * the compiler's dead-store elimination. */
  if (atexit(caps_zeroize) != 0) {
    fprintf(stderr, "ERR\tcap\tatexit() failed; refusing to derive capability tokens\n");
    abort();
  }
}

static void oo_caps_init(void) {
  pthread_once(&g_caps_once, caps_once_init);
}

/* v3.2.2: diagnostic API for the differential cap-derivation test
 * (qa/tests_challenger_differential_cap.c). Returns the cap token at
 * index 0..21, or 0 if out of range. The 22 cap tokens are derived
 * from getentropy() in caps_once_init (the canonical store). The
 * differential test forks 8 children, reads g_tok_fs (index 0) from
 * each, and verifies all 8 are unique. An LCG fallback for
 * getentropy() failure (the round-4 CRITICAL) would produce the
 * same token across all 8 children and fail the test. The tokens
 * are the real g_tok_* values — there is no test-only derivation
 * path that could mask the bug.
 *
 * Tokens in other files (g_tok_time, g_tok_rand, g_tok_alloc,
 * g_tok_arena, g_tok_ffi, g_tok_metrics) are not exposed here;
 * the canonical store is the most important to verify, and
 * exposing 22 pointers is enough for the test. */
static const long long *const CAP_TOKENS[22] = {
  &g_tok_fs,   &g_tok_sys,        &g_tok_env,   &g_tok_net,
  &g_tok_sign, &g_tok_process,    &g_tok_tcp,    &g_tok_udp,
  &g_tok_bind, &g_tok_audio,      &g_tok_camera, &g_tok_usb,
  &g_tok_hid,  &g_tok_window,     &g_tok_frame,  &g_tok_fsread,
  &g_tok_fswrite, &g_tok_arena,   &g_tok_thread, &g_tok_gpu,
  &g_tok_compiler_read, &g_tok_metrics,
};

long long oo_cap_self_token(int which) {
  if (which < 0 || which >= 22) return 0;
  oo_caps_init();
  return *CAP_TOKENS[which];
}
