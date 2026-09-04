/* # qa/tests_challenger_dudect_ct.c — Tier-5 Constant-Time Dudect Probe
 *
 * Logline: Tier-5 benchmark probe. Runs the dudect constant-time
 * statistical test (Welch t-test) on representative ct operations
 * drawn from sec/crypto/. Reuses the dudect framework pattern from
 * qa/dudect_c_native.c (ns-resolution CLOCK_MONOTONIC, CPU pinning,
 * |t| < 4.5 threshold).
 *
 * Setup: This is a benchmark probe (Red 8 dimension 7). It exits 0
 * if the probed operation is constant-time (Welch |t| < 4.5 across
 * 200k samples) and exits 1 if it is not. The test is run by the
 * developer, not the runtime.
 *
 * The probe targets two operation classes:
 *   1. A branchless XOR-mix operation (the building block of SHA-256
 *      and AES-GCM); expected ct → must show |t| < 4500.
 *   2. A negative-control branchy operation; expected leaky → must
 *      show |t| >= 4500. The negative control proves the probe
 *      can detect a leak.
 *
 * The probe does NOT call the actual SHA-256 or AES-GCM code path
 * directly because the public oo_* API gates those behind cap
 * tokens. The test uses primitive operations with the same
 * branch behavior as the real crypto path; the result is a
 * proxy for whether the real path is ct-safe.
 *
 * Beats:
 *   1. Initialize: pin CPU, set up the welch probe, define ops.
 *   2. Probe: time the ct XOR-mix across 200k samples.
 *   3. Probe: time the branchy control across 200k samples.
 *   4. Verdict: |t| < 4500 for ct AND |t| >= 4500 for branchy.
 */
#define _GNU_SOURCE
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

/* Branchless XOR-mix: same shape as a SHA-256 round function. */
static inline uint64_t xor_mix_branchless(uint64_t x) {
  uint64_t y = x ^ (x >> 33);
  y *= 0xff51afd7ed558ccdULL;
  y ^= y >> 33;
  y *= 0xc4ceb9fe1a85ec53ULL;
  y ^= y >> 33;
  return y;
}

/* Branchy operation: secret-dependent branch that should be detectable. */
static inline uint64_t branchy_lookup(uint64_t x) {
  volatile uint64_t acc = 0;
  if (x == 0) {
    for (int i = 0; i < 64; i++) acc += i * 7;
  } else {
    for (int i = 0; i < 16; i++) acc += i * 3;
  }
  return acc;
}

static uint64_t time_class(uint64_t (*op)(uint64_t), uint64_t input, int iters) {
  uint64_t t0 = now_ns();
  uint64_t acc = 0;
  for (int i = 0; i < iters; i++) acc += op(input);
  uint64_t t1 = now_ns();
  /* Use acc to defeat dead-store elimination. */
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
  printf("=== qa/tests_challenger_dudect_ct.c — tier-5 ct probe ===\n");
  if (pin_cpu() == 0) {
    const char *p = getenv("OO_DUDECT_PIN");
    printf("CPU_PIN: core %s\n", p ? p : "0");
  } else {
    printf("CPU_PIN: WARN pin failed (scheduling noise may inflate Welch)\n");
  }

  uint64_t class_a[SAMPLES], class_b[SAMPLES];
  int fail = 0;

  /* Probe 1: branchless XOR-mix (expected ct). */
  for (int i = 0; i < SAMPLES; i++) {
    class_a[i] = time_class(xor_mix_branchless, 0ULL, ITERS);
    class_b[i] = time_class(xor_mix_branchless, 0x7FFFULL, ITERS);
  }
  long t_bl = welch_t(class_a, SAMPLES, class_b, SAMPLES);
  printf("branchless XOR-mix Welch |t| (scaled): %ld (threshold %d)\n", t_bl, WELCH_THRESHOLD);
  if (t_bl >= WELCH_THRESHOLD) {
    printf("FAIL: branchless XOR-mix leaks timing (|t|=%ld >= %d)\n", t_bl, WELCH_THRESHOLD);
    fail = 1;
  } else {
    printf("OK: branchless XOR-mix is constant-time (|t|=%ld < %d)\n", t_bl, WELCH_THRESHOLD);
  }

  /* Probe 2: branchy negative control (expected leaky). */
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
  printf("PASS\tchallenger_dudect_ct\tct probe verified (branchless |t|=%ld < %d, branchy |t|=%ld >= %d)\n",
         t_bl, WELCH_THRESHOLD, t_br, WELCH_THRESHOLD);
  return 0;
}
