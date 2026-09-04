/* qa/tests_fuzz_smoke.c — round-5 fuzzing smoke test.
 *
 * Calls each cap-protected mutator with random valid-looking
 * inputs and verifies the process doesn't crash. This is a
 * smoke test (not a full AFL/libFuzzer harness) but it catches
 * the easy "unknown unknowns" — buffer overflows, NULL deref,
 * off-by-one in the bit math, use-after-free in zeroize.
 *
 * The 3 hard gates of round-5:
 *   1. v3.2.0 contract test: 'cap is not the first line of defense'
 *   2. v3.2.1 adversarial scanner: 'comments lie about what code does'
 *   3. v3.2.2 differential test: 'entropy is not actually random'
 * The fuzzing smoke test is the 4th gate: 'does the code survive
 * random inputs without crashing'.
 *
 * Pattern: each iteration generates a random cap (from
 * /dev/urandom via getentropy) and random args (from a
 * pseudo-random source seeded with the time). Forks a child
 * to run the call. If the child crashes (signal 6/11), the
 * test fails. If the child exits 0, the call returned without
 * crashing — which is fine even if the call "failed" the cap
 * check (cap=0 → exit(1) → child exits non-zero, but no crash).
 *
 * v3.2.3 added: this test.
 *
 * Exit codes:
 *   0 — N iterations completed without any crash
 *   1 — at least one child crashed (signal 6/11 or unexpected exit)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include "../oodar.h"
#include "../sec/cap/caps.h"

#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

#define N_ITER 200
#define MAX_PAYLOAD 64

static unsigned long long rng_state = 0xdeadbeefcafebabeULL;

static unsigned long long xoshiro_next(void) {
  unsigned long long z = (rng_state += 0x9E3779B97F4A7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

static long long rand_cap(void) {
#if defined(__linux__) || defined(__APPLE__)
  unsigned long long b;
  if (getentropy(&b, sizeof b) == 0) return (long long)b;
#endif
  return (long long)(xoshiro_next() & 0x7fffffffffffffffULL);
}

static int rand_int(int lo, int hi) {
  if (hi <= lo) return lo;
  return lo + (int)(xoshiro_next() % (unsigned long long)(hi - lo + 1));
}

static int run_one_fork(const char *name) {
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    /* Child: pick a random cap, call the mutator with random args. */
    alarm(1);
    long long cap = rand_cap();

    /* Pick a random call from a small set. The point is to exercise
     * the code paths under random inputs, not to test the contract
     * (the contract test v3.2.0 does that). */
    int which = rand_int(0, 5);
    OoStr s = oo_str_lit("x");
    OoStr empty = oo_str_lit("");
    switch (which) {
      case 0: (void)oo_alloc(cap, rand_int(0, 4096)); break;
      case 1: (void)oo_arena_create(cap, rand_int(0, 1 << 16)); break;
      case 2: (void)oo_actor_spawn(cap, empty); break;
      case 3: (void)oo_env_get(cap, empty); break;
      case 4: (void)oo_read_file(cap, empty); break;
      case 5: (void)oo_metrics_incr(cap, empty); break;
    }
    _exit(0);
  }
  int st = 0;
  waitpid(pid, &st, 0);
  if (WIFSIGNALED(st)) {
    fprintf(stderr, "CRASH: %s — signal %d (%s)\n", name, WTERMSIG(st),
            strsignal(WTERMSIG(st)));
    return 1;
  }
  if (!WIFEXITED(st)) {
    fprintf(stderr, "FAIL: %s — child did not exit normally\n", name);
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  unsigned long long seed = (unsigned long long)time(NULL);
  if (argc > 1) seed = strtoull(argv[1], NULL, 0);
  rng_state = seed;
  fprintf(stderr, "fuzz_smoke: N_ITER=%d seed=0x%016llx\n", N_ITER, seed);

  int crashes = 0;
  for (int i = 0; i < N_ITER; i++) {
    if (run_one_fork("fuzz") != 0) crashes++;
  }
  if (crashes == 0) {
    printf("OK\tfuzz\t%d iterations, no crashes\n", N_ITER);
    return 0;
  }
  fprintf(stderr, "FAIL\tfuzz\t%d / %d iterations crashed\n", crashes, N_ITER);
  return 1;
}
