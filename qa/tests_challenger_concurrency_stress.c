/* qa/tests_challenger_concurrency_stress.c — High-throughput concurrency stress.
 * Validates multi-thread list allocations, COW retention across threads, zero
 * ambient quota drift, multi-producer/consumer actor channels, channel
 * teardown under active sends, and out-of-quota fail-closed recovery.
 * Exit codes: 0 = PASS, 1 = FAIL. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>
#include "../oodar.h"
#include "../types.h"

#define NUM_LIST_THREADS 8
#define LIST_ITERS 100
#define NUM_PROD 4
#define NUM_CONS 4
#define MSGS_PER_PROD 100
#define TOTAL_MSGS (NUM_PROD * MSGS_PER_PROD)

static int fails = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { fprintf(stderr, "FAIL\tconcurrency_stress\t%s\n", msg); fails++; } \
} while (0)

static void *list_worker(void *arg) {
  long long tid = (long long)(intptr_t)arg;
  for (int iter = 0; iter < LIST_ITERS; iter++) {
    OoIList il = oo_ilist_new();
    for (int j = 0; j < 8; j++) {
      OoIList t = il; il = oo_ilist_push(il, (tid * 1000LL) + j); oo_ilist_release(t);
    }
    if (oo_ilist_len(il) != 8) __atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED);
    for (int j = 0; j < 8; j++)
      if (oo_ilist_get(il, j) != (tid * 1000LL) + j) __atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED);
    oo_ilist_release(il);

    OoFList fl = oo_flist_new();
    for (int j = 0; j < 6; j++) {
      OoFList t = fl; fl = oo_flist_push(fl, (double)(tid * 10 + j)); oo_flist_release(t);
    }
    if (oo_flist_len(fl) != 6) __atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED);
    for (int j = 0; j < 6; j++)
      if (oo_flist_get(fl, j) != (double)(tid * 10 + j)) __atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED);
    oo_flist_release(fl);

    OoSList sl = oo_slist_new();
    for (int j = 0; j < 4; j++) {
      OoSList t = sl; sl = oo_slist_push(sl, oo_str_lit("stress")); oo_slist_release(t);
    }
    if (oo_slist_len(sl) != 4) __atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED);
    for (int j = 0; j < 4; j++) {
      OoStr s = oo_slist_get(sl, j);
      if (!oo_str_eq(s, oo_str_lit("stress"))) __atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED);
      oo_str_release(s);
    }
    oo_slist_release(sl);
  }
  return NULL;
}

typedef struct { OoIList shared; int id; } cow_arg_t;

static void *cow_worker(void *arg_) {
  cow_arg_t *a = (cow_arg_t *)arg_;
  if (oo_ilist_len(a->shared) != 3 || oo_ilist_get(a->shared, 0) != 10 ||
      oo_ilist_get(a->shared, 1) != 20 || oo_ilist_get(a->shared, 2) != 30)
    __atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED);
  OoIList loc = oo_ilist_push(a->shared, 100LL + a->id);
  if (oo_ilist_len(loc) != 4 || oo_ilist_get(loc, 3) != 100LL + a->id)
    __atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED);
  oo_ilist_release(loc);
  oo_ilist_release(a->shared);
  return NULL;
}

static void test_concurrent_lists_and_cow(void) {
  pthread_t ths[NUM_LIST_THREADS];
  long long b0 = oo_list_ambient_bytes;
  for (int i = 0; i < NUM_LIST_THREADS; i++)
    pthread_create(&ths[i], NULL, list_worker, (void *)(intptr_t)(i + 1));
  for (int i = 0; i < NUM_LIST_THREADS; i++) pthread_join(ths[i], NULL);

  OoIList base = oo_ilist_new();
  OoIList t1 = base; base = oo_ilist_push(base, 10); oo_ilist_release(t1);
  OoIList t2 = base; base = oo_ilist_push(base, 20); oo_ilist_release(t2);
  OoIList t3 = base; base = oo_ilist_push(base, 30); oo_ilist_release(t3);

  pthread_t cow_ths[4];
  cow_arg_t cargs[4];
  for (int i = 0; i < 4; i++) {
    oo_ilist_retain(base);
    cargs[i].shared = base; cargs[i].id = i;
    pthread_create(&cow_ths[i], NULL, cow_worker, &cargs[i]);
  }
  for (int i = 0; i < 4; i++) pthread_join(cow_ths[i], NULL);
  CHECK(oo_ilist_len(base) == 3, "COW base list untouched by worker pushes");
  oo_ilist_release(base);
  CHECK(b0 == oo_list_ambient_bytes, "oo_list_ambient_bytes no-drift after multi-thread alloc/free");
}

typedef struct { long long cap; long long slot; int prod_id; } prod_arg_t;
typedef struct { long long cap; long long slot; } cons_arg_t;
static int g_msgs_received = 0;

static void *prod_worker(void *arg_) {
  prod_arg_t *a = (prod_arg_t *)arg_;
  for (int i = 0; i < MSGS_PER_PROD; i++) {
    char buf[64]; snprintf(buf, sizeof buf, "p%d:%d", a->prod_id, i);
    OoResS r; int tries = 0;
    do {
      r = oo_channel_send(a->cap, a->slot, oo_str_lit(buf));
      if (!r.ok) {
        usleep(15);
        if (++tries > 200000) {
          fprintf(stderr, "FAIL\tconcurrency_stress\tsend deadlock timeout\n");
          __atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED);
          return NULL;
        }
      }
    } while (!r.ok);
  }
  return NULL;
}

static void *cons_worker(void *arg_) {
  cons_arg_t *a = (cons_arg_t *)arg_;
  int empty_spins = 0;
  while (__atomic_load_n(&g_msgs_received, __ATOMIC_RELAXED) < TOTAL_MSGS) {
    OoResS r = oo_channel_recv(a->cap, a->slot);
    if (r.ok) {
      __atomic_fetch_add(&g_msgs_received, 1, __ATOMIC_RELAXED);
      oo_str_release(r.val);
      empty_spins = 0;
    } else {
      usleep(10);
      if (++empty_spins > 300000) break;
    }
  }
  return NULL;
}

static void test_concurrent_channel(void) {
  long long cap = oo_cap_grant_thread();
  OoResS ch_res = oo_channel_new(cap);
  CHECK(ch_res.ok, "channel_new succeeded");
  if (!ch_res.ok) return;

  long long slot = -1;
  sscanf(ch_res.val.data, "ch:%lld", &slot);
  oo_str_release(ch_res.val);
  CHECK(slot >= 0, "channel slot parsed");

  pthread_t prods[NUM_PROD], conss[NUM_CONS];
  prod_arg_t pargs[NUM_PROD]; cons_arg_t cargs[NUM_CONS];
  g_msgs_received = 0;

  for (int i = 0; i < NUM_CONS; i++) {
    cargs[i].cap = cap; cargs[i].slot = slot;
    pthread_create(&conss[i], NULL, cons_worker, &cargs[i]);
  }
  for (int i = 0; i < NUM_PROD; i++) {
    pargs[i].cap = cap; pargs[i].slot = slot; pargs[i].prod_id = i;
    pthread_create(&prods[i], NULL, prod_worker, &pargs[i]);
  }

  for (int i = 0; i < NUM_PROD; i++) pthread_join(prods[i], NULL);
  for (int i = 0; i < NUM_CONS; i++) pthread_join(conss[i], NULL);

  CHECK(g_msgs_received == TOTAL_MSGS, "exact total messages delivered");
  OoResS d_res = oo_channel_destroy(cap, slot);
  CHECK(d_res.ok, "channel_destroy succeeded");
  oo_str_release(d_res.val);
}

static void *teardown_sender(void *arg) {
  long long *args = (long long *)arg;
  long long cap = args[0], slot = args[1];
  for (int i = 0; i < 50000; i++) {
    OoResS r = oo_channel_send(cap, slot, oo_str_lit("teardown_probe"));
    if (!r.ok) break; /* Once destroyed, channel_send safely returns ok=0 */
    usleep(5);
  }
  return NULL;
}

static void test_channel_teardown_race(void) {
  long long cap = oo_cap_grant_thread();
  OoResS ch_res = oo_channel_new(cap);
  CHECK(ch_res.ok, "teardown channel_new ok");
  long long slot = -1;
  sscanf(ch_res.val.data, "ch:%lld", &slot);
  oo_str_release(ch_res.val);

  pthread_t th;
  long long args[2] = { cap, slot };
  pthread_create(&th, NULL, teardown_sender, args);
  usleep(500);
  OoResS d_res = oo_channel_destroy(cap, slot);
  CHECK(d_res.ok, "teardown channel_destroy ok");
  oo_str_release(d_res.val);
  pthread_join(th, NULL);
}

static void test_quota_overflow_fail_closed_and_recovery(void) {
  long long b_before = oo_list_ambient_bytes;
  pid_t pid = fork();
  if (pid == 0) {
    alarm(5);
    oo_list_ambient_quota = 1024 * 1024;
    oo_list_alloc_payload(sizeof(long long), 2 * 1024 * 1024);
    _exit(0);
  }
  int st = 0;
  waitpid(pid, &st, 0);
  CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 1, "quota overflow terminated fail-closed exit(1)");
  CHECK(oo_list_ambient_bytes == b_before, "parent quota intact after child overflow");

  OoIList rec = oo_ilist_new();
  for (int i = 0; i < 10; i++) {
    OoIList t = rec; rec = oo_ilist_push(rec, i * 7); oo_ilist_release(t);
  }
  CHECK(oo_ilist_len(rec) == 10, "parent allocated after child failure");
  for (int i = 0; i < 10; i++) CHECK(oo_ilist_get(rec, i) == i * 7, "value ok");
  oo_ilist_release(rec);
  CHECK(oo_list_ambient_bytes == b_before, "zero drift after recovery");
}

int main(void) {
  alarm(30);
  test_concurrent_lists_and_cow();
  test_concurrent_channel();
  test_channel_teardown_race();
  test_quota_overflow_fail_closed_and_recovery();

  if (fails == 0) {
    printf("OK\tconcurrency_stress\tlists+COW+actors+teardown+recovery validated\n");
    return 0;
  }
  fprintf(stderr, "FAIL\tconcurrency_stress\t%d failures\n", fails);
  return 1;
}
