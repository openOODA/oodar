/* qa/tests_challenger_differential_cap.c — cap token distribution test.
 *
 * Round-5 deep-dive: differential test for cap token derivation.
 * Forks 8 children, reads g_tok_fs (and the other 25 canonical
 * tokens) from each via oo_cap_self_token(), and verifies the
 * tokens are all unique. An LCG fallback for getentropy()
 * failure (the round-4 CRITICAL) would produce the same token
 * across all 8 children (same pid, same getpid(), same
 * monotonic_us() — the LCG seed is deterministic for forks) and
 * fail the test.
 *
 * The 4 round-4 CRITICALs (LCG fallbacks in time_rand.c and
 * crypto.c) would have been caught by this test had it existed.
 * The test reads the production g_tok_* values directly — there
 * is no test-only derivation path that could mask the bug.
 *
 * v3.2.2 added: this test + the oo_cap_self_token diagnostic API
 * in sec/cap/caps.h:146.
 *
 * Exit codes:
 *   0 — all 8 cap tokens are unique across all 26 indices
 *   1 — distribution failure (possible LCG fallback)
 *
 * v3.4.1 round-6: bumped from 22 → 26 indices. v3.4.0 added 4 new
 * token sources (g_tok_alloc, g_tok_time, g_tok_rand, g_tok_ffi) now
 * exposed via oo_cap_self_token. The round-6 audit caught that the
 * test was only covering 22 of 26 tokens; 4 were unreachable from
 * the diagnostic. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../oodar.h"
#include "../sec/cap/caps.h"

#define N_CHILDREN 8
#define N_TOKENS   26

static int check_uniqueness(void) {
  long long tokens[N_CHILDREN][N_TOKENS];
  pid_t pids[N_CHILDREN];
  int pipes[N_CHILDREN][2];

  for (int i = 0; i < N_CHILDREN; i++) {
    if (pipe(pipes[i]) < 0) { perror("pipe"); return 1; }
    pids[i] = fork();
    if (pids[i] < 0) { perror("fork"); return 1; }
    if (pids[i] == 0) {
      /* Child: close read end, write all 26 cap tokens. */
      alarm(2);
      for (int j = 0; j < N_TOKENS; j++) {
        long long tok = oo_cap_self_token(j);
        write(pipes[i][1], &tok, sizeof(tok));
      }
      close(pipes[i][1]);
      _exit(0);
    }
    close(pipes[i][1]);
  }

  /* Parent: read all tokens. */
  for (int i = 0; i < N_CHILDREN; i++) {
    for (int j = 0; j < N_TOKENS; j++) {
      ssize_t r = read(pipes[i][0], &tokens[i][j], sizeof(long long));
      if (r != sizeof(long long)) {
        fprintf(stderr, "FAIL\tdiff\tchild %d token %d: short read (%zd bytes)\n", i, j, r);
        close(pipes[i][0]);
        waitpid(pids[i], NULL, 0);
        return 1;
      }
    }
    close(pipes[i][0]);
    waitpid(pids[i], NULL, 0);
  }

  /* Check 1: every token must be non-zero. */
  int nonzero = 0;
  for (int i = 0; i < N_CHILDREN; i++) {
    for (int j = 0; j < N_TOKENS; j++) {
      if (tokens[i][j] == 0) {
        fprintf(stderr, "FAIL\tdiff\tchild %d token %d: zero (silent init failure)\n", i, j);
        return 1;
      }
      nonzero++;
    }
  }
  fprintf(stderr, "diff: %d non-zero tokens (expected %d)\n", nonzero, N_CHILDREN * N_TOKENS);

  /* Check 2: for each token index, all 8 children must have unique values.
   * An LCG fallback would produce the same value across all 8 forks. */
  int failures = 0;
  for (int j = 0; j < N_TOKENS; j++) {
    for (int i = 0; i < N_CHILDREN; i++) {
      for (int k = i + 1; k < N_CHILDREN; k++) {
        if (tokens[i][j] == tokens[k][j]) {
          fprintf(stderr, "FAIL\tdiff\ttoken %d: child %d and %d have same value 0x%016llx (LCG fallback?)\n",
                  j, i, k, (unsigned long long)tokens[i][j]);
          failures++;
        }
      }
    }
  }
  if (failures > 0) {
    fprintf(stderr, "FAIL\tdiff\t%d collisions across %d token indices × %d children\n",
            failures, N_TOKENS, N_CHILDREN);
    return 1;
  }

  /* Print a sample for the human auditor. */
  printf("OK\tdiff\t%d cap tokens × %d children: all unique, all non-zero\n", N_TOKENS, N_CHILDREN);
  for (int j = 0; j < N_TOKENS && j < 4; j++) {
    fprintf(stderr, "  token[%2d]  child[0] = 0x%016llx  child[1] = 0x%016llx\n",
            j, (unsigned long long)tokens[0][j], (unsigned long long)tokens[1][j]);
  }
  return 0;
}

int main(void) {
  return check_uniqueness();
}
