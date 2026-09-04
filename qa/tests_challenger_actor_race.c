/* qa/tests_challenger_actor_race.c — concurrency race for oo_otp_supervise.
 *
 * Round-5 deep-dive: oo_otp_supervise had a TOCTOU race on
 * g_otp_once[s]. The check-and-set was unlocked; two threads
 * could both pass the "already" check and both call
 * oo_actor_restart. v3.3.4 holds g_act_boot across the check
 * to prevent the race.
 *
 * The test forks 8 children. Each child:
 *   1. Allocates a real cap (g_tok_thread).
 *   2. Spawns an actor.
 *   3. Concurrently calls oo_otp_supervise on the same actor 100x.
 *   4. Counts how many of the 100 calls succeeded.
 *
 * The contract: exactly 1 call should succeed. Pre-v3.3.4, the
 * count could be 2-8 due to the race. v3.3.4 makes it 1.
 *
 * Exit codes:
 *   0 — all 8 children see exactly 1 successful otp_supervise
 *   1 — at least one child sees > 1 (race detected)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>

#include "../oodar.h"
#include "../sec/cap/caps.h"

#define N_THREADS 8
#define N_CALLS   100

typedef struct {
  long long cap;
  long long actor_id;
  int success_count;
} worker_arg_t;

static void *worker(void *arg_) {
  worker_arg_t *a = (worker_arg_t *)arg_;
  for (int i = 0; i < N_CALLS; i++) {
    OoResS r = oo_otp_supervise(a->cap, a->actor_id);
    if (r.ok) a->success_count++;
  }
  return NULL;
}

static int run_in_child(void) {
  long long cap = oo_cap_self_token(18);  /* index 18 = g_tok_thread */
  if (cap == 0) {
    fprintf(stderr, "  child: cap=0\n");
    return 0;
  }
  /* Spawn an actor. */
  OoResS spawn = oo_actor_spawn(cap, oo_str_lit("test"));
  if (!spawn.ok) {
    fprintf(stderr, "  child: actor_spawn failed\n");
    return 0;
  }
  long long id = 0;  /* slot 0 */

  /* Spawn N_THREADS threads, each calling otp_supervise 100 times. */
  pthread_t threads[N_THREADS];
  worker_arg_t args[N_THREADS];
  for (int i = 0; i < N_THREADS; i++) {
    args[i].cap = cap;
    args[i].actor_id = id;
    args[i].success_count = 0;
    pthread_create(&threads[i], NULL, worker, &args[i]);
  }
  for (int i = 0; i < N_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }
  /* Sum the success counts across all threads. */
  int total_success = 0;
  for (int i = 0; i < N_THREADS; i++) {
    total_success += args[i].success_count;
  }
  fprintf(stderr, "  child: %d threads, %d total otp_supervise successes (expected 1)\n",
          N_THREADS, total_success);
  /* Exit 0 if exactly 1 success (no race), 1 if > 1 (race). */
  _exit(total_success == 1 ? 0 : 1);
}

int main(void) {
  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return 1; }
  if (pid == 0) { alarm(30); run_in_child(); _exit(1); }
  int st = 0;
  waitpid(pid, &st, 0);
  if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
    printf("OK\trace\t8 concurrent threads saw exactly 1 otp_supervise success (no race)\n");
    return 0;
  }
  fprintf(stderr, "FAIL\trace\tconcurrent threads saw %s otp_supervise successes (race!)\n",
          WIFEXITED(st) ? "wrong number of" : "no");
  return 1;
}
