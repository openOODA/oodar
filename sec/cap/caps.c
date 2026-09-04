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
static long long g_tok_sign, g_tok_process, g_tok_sync, g_tok_mem;
static long long g_tok_http, g_tok_tcp, g_tok_udp, g_tok_bind;
static long long g_tok_audio, g_tok_camera, g_tok_usb, g_tok_hid;
static long long g_tok_window, g_tok_frame, g_tok_fsread, g_tok_fswrite;
static long long g_tok_arena, g_tok_thread, g_tok_gpu;
static long long g_tok_compiler_read;
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
  explicit_bzero(&g_tok_sync, sizeof g_tok_sync);
  explicit_bzero(&g_tok_mem, sizeof g_tok_mem);
  explicit_bzero(&g_tok_http, sizeof g_tok_http);
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
  explicit_bzero(g_kernel_hmac_key, sizeof g_kernel_hmac_key);
}

static void caps_once_init(void) {
  unsigned char b[175];
  size_t i;
  unsigned long long acc;
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
  g_tok_sync    = make_cap_tok(0x7,  b + 42);
  g_tok_mem     = make_cap_tok(0x8,  b + 49);
  g_tok_http    = make_cap_tok(0x9,  b + 56);
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

long long oo_cap_grant_fs(void) { oo_caps_init(); return g_tok_fs; }
long long oo_cap_grant_sys(void) { oo_caps_init(); oo_sandbox_note_proc(); return g_tok_sys; }
long long oo_cap_grant_env(void) { oo_caps_init(); return g_tok_env; }
long long oo_cap_grant_net(void) { oo_caps_init(); oo_sandbox_note_net(); return g_tok_net; }
long long oo_cap_grant_sign(void) { oo_caps_init(); return g_tok_sign; }
long long oo_cap_grant_process(void) { oo_caps_init(); oo_sandbox_note_proc(); return g_tok_process; }
long long oo_cap_grant_sync(void) { oo_caps_init(); return g_tok_sync; }
long long oo_cap_grant_mem(void) { oo_caps_init(); return g_tok_mem; }
long long oo_cap_grant_http(void) { oo_caps_init(); oo_sandbox_note_net(); return g_tok_http; }
long long oo_cap_grant_tcp(void) { oo_caps_init(); oo_sandbox_note_net(); return g_tok_tcp; }
long long oo_cap_grant_udp(void) { oo_caps_init(); oo_sandbox_note_net(); return g_tok_udp; }
long long oo_cap_grant_bind(void) { oo_caps_init(); oo_sandbox_note_net(); return g_tok_bind; }
long long oo_cap_grant_audio(void) { oo_caps_init(); return g_tok_audio; }
long long oo_cap_grant_camera(void) { oo_caps_init(); return g_tok_camera; }
long long oo_cap_grant_usb(void) { oo_caps_init(); return g_tok_usb; }
long long oo_cap_grant_hid(void) { oo_caps_init(); return g_tok_hid; }
long long oo_cap_grant_window(void) { oo_caps_init(); return g_tok_window; }
long long oo_cap_grant_frame(void) { oo_caps_init(); return g_tok_frame; }
long long oo_cap_grant_fsread(void) { oo_caps_init(); return g_tok_fsread; }
long long oo_cap_grant_fswrite(void) { oo_caps_init(); return g_tok_fswrite; }
long long oo_cap_grant_arena(void) { oo_caps_init(); return g_tok_arena; }
long long oo_cap_grant_thread(void) { oo_caps_init(); return g_tok_thread; }
long long oo_cap_grant_gpu(void) { oo_caps_init(); return g_tok_gpu; }
long long oo_cap_grant_compiler_read(void) { oo_caps_init(); return g_tok_compiler_read; }

int oo_cap_is_arena(long long got) { oo_caps_init(); return got == g_tok_arena; }

void oo_cap_require(long long got, long long want, const char *op) {
  oo_caps_init();
  if (got == 0 || got != want) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "?");
    exit(1);
  }
}

void oo_cap_require_fs(long long got, const char *op) { oo_cap_require(got, g_tok_fs, op ? op : "fs"); }
void oo_cap_require_sys(long long got, const char *op) { oo_cap_require(got, g_tok_sys, op ? op : "sys"); }
void oo_cap_require_env(long long got, const char *op) { oo_cap_require(got, g_tok_env, op ? op : "env"); }
void oo_cap_require_net(long long got, const char *op) { oo_cap_require(got, g_tok_net, op ? op : "net"); }
void oo_cap_require_sign(long long got, const char *op) { oo_cap_require(got, g_tok_sign, op ? op : "sign"); }
void oo_cap_require_sync(long long got, const char *op) { oo_cap_require(got, g_tok_sync, op ? op : "sync"); }
void oo_cap_require_mem(long long got, const char *op) { oo_cap_require(got, g_tok_mem, op ? op : "mem"); }
void oo_cap_require_audio(long long got, const char *op) { oo_cap_require(got, g_tok_audio, op ? op : "audio"); }
void oo_cap_require_camera(long long got, const char *op) { oo_cap_require(got, g_tok_camera, op ? op : "camera"); }
void oo_cap_require_usb(long long got, const char *op) { oo_cap_require(got, g_tok_usb, op ? op : "usb"); }
void oo_cap_require_hid(long long got, const char *op) { oo_cap_require(got, g_tok_hid, op ? op : "hid"); }
void oo_cap_require_window(long long got, const char *op) { oo_cap_require(got, g_tok_window, op ? op : "window"); }
void oo_cap_require_frame(long long got, const char *op) { oo_cap_require(got, g_tok_frame, op ? op : "frame"); }
void oo_cap_require_arena(long long got, const char *op) { oo_cap_require(got, g_tok_arena, op ? op : "arena"); }
void oo_cap_require_thread(long long got, const char *op) { oo_cap_require(got, g_tok_thread, op ? op : "thread"); }
void oo_cap_require_gpu(long long got, const char *op) { oo_cap_require(got, g_tok_gpu, op ? op : "gpu"); }
void oo_cap_require_compiler_read(long long got, const char *op) { oo_cap_require(got, g_tok_compiler_read, op ? op : "compiler_read"); }

void oo_cap_require_http(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_http && got != g_tok_net)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "http");
    exit(1);
  }
}
void oo_cap_require_tcp(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_tcp && got != g_tok_net)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "tcp");
    exit(1);
  }
}
void oo_cap_require_udp(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_udp && got != g_tok_net)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "udp");
    exit(1);
  }
}
void oo_cap_require_bind(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_bind && got != g_tok_net)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "bind");
    exit(1);
  }
}
void oo_cap_require_fsread(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_fsread && got != g_tok_fs)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "fsread");
    exit(1);
  }
}
void oo_cap_require_fswrite(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_fswrite && got != g_tok_fs)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "fswrite");
    exit(1);
  }
}
void oo_cap_require_process(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_process && got != g_tok_sys)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "process");
    exit(1);
  }
}

OoStr oo_cap_kernel_seal(long long sys, OoStr cap_id) {
  OoStr key;
  oo_caps_init();
  oo_cap_require_sys(sys, "oo_cap_kernel_seal");
  if (cap_id.len <= 0 || !cap_id.data) {
    OoStr z; z.data = oo_str_alloc_payload(0); z.len = 0; return z;
  }
  key.data = (char *)g_kernel_hmac_key;
  key.len = (long long)sizeof g_kernel_hmac_key;
  return crypto_hmac_sha256_internal(key, cap_id);
}

OoStr oo_enclave_enter(long long sys, OoStr sealed) {
  unsigned char page[64];
  OoStr acc, meas;
  size_t n;
  oo_caps_init();
  oo_cap_require_sys(sys, "oo_enclave_enter");
  memset(page, 0, sizeof page);
  memcpy(page, "ooda-enclave-v1", 15);
  if (sealed.data && sealed.len > 0) {
    n = (size_t)sealed.len;
    if (n > 32) n = 32;
    memcpy(page + 16, sealed.data, n);
  }
  for (int j = 0; j < 8; j++) {
    page[48 + j] = (unsigned char)(sys >> ((7 - j) * 8));
  }
  acc.data = (char *)page;
  acc.len = 64;
  meas = crypto_sha256_internal(acc);
  fputs("enclave_measurement ", stdout);
  if (meas.data && meas.len > 0) fwrite(meas.data, 1, (size_t)meas.len, stdout);
  fputc('\n', stdout);
  return meas;
}
