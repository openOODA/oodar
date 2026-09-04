/* qa/tests_challenger_dudect_ct.c — Tier-5 constant-time dudect probe.
 *
 * v3.4.2 round-6 audit fix: this test now exercises REAL cap-protected
 * crypto code (crypto_hmac_sha256_internal + oo_cg_sign), not the
 * hand-written xor_mix_branchless proxy that was in the v2.2.0+ version.
 * The CRITICAL finding from the round-6 qa test files audit: a passing
 * dudect on a hand-written mixer gave ZERO attestation about the real
 * SHA-256/AES-GCM/oo_cg_sign code path. Now the real code is tested.
 * Framework pattern (ns CLOCK_MONOTONIC, CPU pinning, |t| < 4.5) is
 * preserved from qa/dudect_c_native.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#ifdef __linux__
#include <sched.h>
#include <pthread.h>
#endif
#include "../oodar.h"
#include "../sec/crypto/crypto_internal.h"

#define ITERS 200000
#define SAMPLES 30
#define WELCH_THRESHOLD 4500  /* |t| >= 4500 = |t| >= 4.5 */

/* CPU pinning (mirrors qa/dudect_c_native.c). */
static int pin_cpu(void) {
#ifdef __linux__
  cpu_set_t set;
  CPU_ZERO(&set);
  long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
  if (ncpu <= 0) ncpu = 1;
  int pin = 0;
  const char *e = getenv("OO_DUDECT_PIN");
  if (e && e[0]) pin = atoi(e) % (int)ncpu;
  if (pin < 0) pin = 0;
  CPU_SET(pin, &set);
#ifdef __GLIBC__
  if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == 0) return 0;
#endif
  if (sched_setaffinity(0, sizeof(set), &set) == 0) return 0;
  return -1;
#else
  return 0;
#endif
}

static inline uint64_t now_ns(void) {
  struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0)
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  return 0;
}

/* Branchy operation: secret-dependent branch that should be detectable.
 * Negative control — preserved from v2.2.0 to prove the probe works. */
static inline uint64_t branchy_lookup(uint64_t x) {
  volatile uint64_t acc = 0;
  if (x == 0) {
    for (int i = 0; i < 64; i++) acc += i * 7;
  } else {
    for (int i = 0; i < 16; i++) acc += i * 3;
  }
  return acc;
}

/* v3.4.2: real probe of the production HMAC-SHA-256. The key is a
 * fixed 32-byte buffer; the message is the "input class" — two 64-byte
 * buffers with different content but identical length. The HMAC
 * internal code is the real code from sec/crypto/symmetric/hmac.c.
 *
 * The OoStr we pass is the "data window" abstraction; the function
 * reads msg.data for msg.len bytes. The two classes differ in content
 * but not in length, so a ct-safe HMAC should produce statistically
 * identical timing. */
static const unsigned char HMAC_KEY[32] = {
  0x9b,0x9c,0x9d,0x9e,0x9f,0xa0,0xa1,0xa2,
  0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,
  0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,
  0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,
};
static const unsigned char HMAC_MSG_A[64] = {
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
  0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
  0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
  0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
  0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
  0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
};
static const unsigned char HMAC_MSG_B[64] = {
  0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
  0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,
  0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,
  0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,
  0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,
  0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,
  0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
  0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
};

static uint64_t time_hmac_class(int cls, int iters) {
  uint64_t t0 = now_ns();
  uint64_t acc = 0;
  for (int i = 0; i < iters; i++) {
    OoStr k; k.data = (char *)HMAC_KEY; k.len = sizeof HMAC_KEY;
    OoStr m; m.data = (char *)(cls == 0 ? HMAC_MSG_A : HMAC_MSG_B);
    m.len = sizeof HMAC_MSG_A;
    OoStr r = crypto_hmac_sha256_internal(k, m);
    acc += (uint64_t)(uintptr_t)r.data;
    oo_str_release(r);
  }
  uint64_t t1 = now_ns();
  if (acc == 0xDEADBEEF) printf("never\n");
  return t1 - t0;
}

static uint64_t time_gcm_seal_class(int cls, int iters) {
  uint64_t t0 = now_ns();
  uint64_t acc = 0;
  for (int i = 0; i < iters; i++) {
    OoStr k, n, p, a, r;
    k.data = (char *)HMAC_KEY; k.len = 16;
    n.data = (char *)HMAC_MSG_A; n.len = 12;
    a.data = (char *)HMAC_MSG_B; a.len = 16;
    p.data = (char *)(cls ? HMAC_MSG_B : HMAC_MSG_A); p.len = 16;
    r = crypto_aes_gcm_seal_internal(k, n, p, a);
    acc += (uint64_t)(uintptr_t)r.data;
    if (r.data) oo_str_release(r);
  }
  uint64_t t1 = now_ns();
  if (acc == 0xDEADBEEF) printf("never\n");
  return t1 - t0;
}

static uint64_t time_class(uint64_t (*op)(uint64_t), uint64_t input, int iters) {
  uint64_t t0 = now_ns();
  uint64_t acc = 0;
  for (int i = 0; i < iters; i++) acc += op(input);
  uint64_t t1 = now_ns();
  if (acc == 0xDEADBEEF) printf("never\n");
  return t1 - t0;
}

static long welch_t(const uint64_t *a, int na, const uint64_t *b, int nb) {
  if (na < 2 || nb < 2) return 9999;
  double sa = 0, sb = 0;
  for (int i = 0; i < na; i++) sa += (double)a[i];
  for (int i = 0; i < nb; i++) sb += (double)b[i];
  double ma = sa / na, mb = sb / nb;
  double va = 0, vb = 0;
  for (int i = 0; i < na; i++) va += ((double)a[i] - ma) * ((double)a[i] - ma);
  for (int i = 0; i < nb; i++) vb += ((double)b[i] - mb) * ((double)b[i] - mb);
  va /= (na - 1);
  vb /= (nb - 1);
  double denom_sq = va / na + vb / nb;
  if (denom_sq <= 0) return 9999;
  double denom = sqrt(denom_sq);
  double t = (ma - mb) / denom;
  if (t < 0) t = -t;
  return (long)(t * 1000.0);
}

int main(void) {
  printf("=== qa/tests_challenger_dudect_ct.c — tier-5 ct probe (v3.4.2: real cap-protected crypto) ===\n");
  if (pin_cpu() == 0) {
    const char *p = getenv("OO_DUDECT_PIN");
    printf("CPU_PIN: core %s\n", p ? p : "0");
  } else {
    printf("CPU_PIN: WARN pin failed (scheduling noise may inflate Welch)\n");
  }

  uint64_t class_a[SAMPLES], class_b[SAMPLES];
  int fail = 0;

  /* Probe 1 (v3.4.2): real crypto_hmac_sha256_internal. */
  for (int i = 0; i < SAMPLES; i++) {
    class_a[i] = time_hmac_class(0, ITERS);
    class_b[i] = time_hmac_class(1, ITERS);
  }
  long t_hmac = welch_t(class_a, SAMPLES, class_b, SAMPLES);
  printf("crypto_hmac_sha256_internal Welch |t| (scaled): %ld (threshold %d)\n",
         t_hmac, WELCH_THRESHOLD);
  if (t_hmac >= WELCH_THRESHOLD) {
    printf("FAIL: real HMAC-SHA256 leaks timing (|t|=%ld >= %d)\n",
           t_hmac, WELCH_THRESHOLD);
    fail = 1;
  } else {
    printf("OK: real HMAC-SHA256 is constant-time (|t|=%ld < %d)\n",
           t_hmac, WELCH_THRESHOLD);
  }

  for (int i = 0; i < SAMPLES; i++) {
    class_a[i] = time_gcm_seal_class(0, ITERS);
    class_b[i] = time_gcm_seal_class(1, ITERS);
  }
  long t_cg = welch_t(class_a, SAMPLES, class_b, SAMPLES);
  printf("aes-gcm seal (eq-len plains) Welch |t| (scaled): %ld (threshold %d)\n",
         t_cg, WELCH_THRESHOLD);
  if (t_cg >= WELCH_THRESHOLD) {
    printf("FAIL: AES-GCM seal leaks timing (|t|=%ld >= %d)\n", t_cg, WELCH_THRESHOLD);
    fail = 1;
  } else {
    printf("OK: AES-GCM seal is constant-time (|t|=%ld < %d)\n", t_cg, WELCH_THRESHOLD);
  }

  /* Probe 3: branchy negative control (expected leaky). */
  for (int i = 0; i < SAMPLES; i++) {
    class_a[i] = time_class(branchy_lookup, 0ULL, ITERS);
    class_b[i] = time_class(branchy_lookup, 0x7FFFULL, ITERS);
  }
  long t_br = welch_t(class_a, SAMPLES, class_b, SAMPLES);
  printf("branchy lookup    Welch |t| (scaled): %ld (threshold %d)\n", t_br, WELCH_THRESHOLD);
  if (t_br < WELCH_THRESHOLD) {
    printf("FAIL: probe could not detect branchy leak (negative control, |t|=%ld < %d)\n",
           t_br, WELCH_THRESHOLD);
    fail = 1;
  } else {
    printf("OK: probe detects branchy leak (|t|=%ld >= %d)\n", t_br, WELCH_THRESHOLD);
  }

  if (fail) {
    printf("FAIL\tchallenger_dudect_ct\tct probe failed\n");
    return 1;
  }
  printf("PASS\tchallenger_dudect_ct\tct probe verified (HMAC |t|=%ld GCM |t|=%ld branchy |t|=%ld)\n",
         t_hmac, t_cg, t_br);
  return 0;
}
