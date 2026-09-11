/* qa/tests_challenger_perf_benchmark.c — Runtime primitive performance validation.
 * Measures and validates real throughput floors for:
 * 1. String search & index matching (oo_str_contains, oo_str_index_of).
 * 2. String construction & slicing (oo_str_concat, oo_byte_slice).
 * 3. List allocation & mutation (oo_ilist_push, oo_ilist_get).
 * 4. Actor channel send / receive throughput.
 * 5. File metadata query latency (oo_path_exists, oo_file_size).
 * Exit codes: 0 = PASS, 1 = FAIL. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "../oodar.h"
#include "../types.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { fprintf(stderr, "FAIL\tperf_benchmark\t%s\n", msg); fails++; } \
} while (0)

static void bench_strings(void) {
  char hay_buf[2048];
  memset(hay_buf, 'a', sizeof(hay_buf) - 1);
  memcpy(hay_buf + 500, "TARGET_INFIX_PATTERN", 20);
  memcpy(hay_buf + sizeof(hay_buf) - 25, "END_PATTERN_ZZZ", 15);
  hay_buf[sizeof(hay_buf) - 1] = 0;
  OoStr hay = { hay_buf, (long long)strlen(hay_buf) };

  OoStr n1 = oo_str_lit("TARGET_INFIX_PATTERN");
  OoStr n2 = oo_str_lit("END_PATTERN_ZZZ");
  OoStr n3 = oo_str_lit("NONEXISTENT_KEYWORD");

  long long t0 = oo_monotonic_us();
  const int iters = 20000;
  for (int i = 0; i < iters; i++) {
    if (!oo_str_contains(hay, n1)) fails++;
    if (!oo_str_contains(hay, n2)) fails++;
    if (oo_str_contains(hay, n3)) fails++;
    if (oo_str_index_of(hay, n1) != 500) fails++;
  }
  long long elapsed_us = oo_monotonic_us() - t0;
  if (elapsed_us <= 0) elapsed_us = 1;
  long long total_ops = (long long)iters * 4;
  long long ops_per_sec = (total_ops * 1000000LL) / elapsed_us;
  CHECK(ops_per_sec >= 50000, "string search throughput >= 50,000 ops/s");
  printf("  perf: string search: %lld ops in %lld us (%lld ops/s)\n",
         total_ops, elapsed_us, ops_per_sec);

  t0 = oo_monotonic_us();
  const int manip_iters = 10000;
  for (int i = 0; i < manip_iters; i++) {
    OoStr c = oo_str_concat(oo_str_lit("token_prefix_"), oo_str_lit("suffix_value"));
    OoStr s = oo_byte_slice(c, 6, 12);
    oo_str_release(s);
    oo_str_release(c);
  }
  elapsed_us = oo_monotonic_us() - t0;
  if (elapsed_us <= 0) elapsed_us = 1;
  long long manip_ops_sec = ((long long)manip_iters * 1000000LL) / elapsed_us;
  CHECK(manip_ops_sec >= 15000, "string manip throughput >= 15,000 ops/s");
  printf("  perf: string concat+slice: %d ops in %lld us (%lld ops/s)\n",
         manip_iters, elapsed_us, manip_ops_sec);
}

static void bench_lists(void) {
  const int iters = 30000;
  long long t0 = oo_monotonic_us();
  OoIList l = oo_ilist_new();
  for (int i = 0; i < iters; i++) {
    OoIList tmp = l;
    l = oo_ilist_push(l, (long long)i);
    oo_ilist_release(tmp);
  }
  for (int i = 0; i < iters; i += 20) {
    long long v = oo_ilist_get(l, i);
    if (v != i) fails++;
  }
  oo_ilist_release(l);
  long long elapsed_us = oo_monotonic_us() - t0;
  if (elapsed_us <= 0) elapsed_us = 1;
  long long ops_per_sec = ((long long)iters * 1000000LL) / elapsed_us;
  CHECK(ops_per_sec >= 50000, "list push throughput >= 50,000 ops/s");
  printf("  perf: list push/get: %d ops in %lld us (%lld ops/s)\n",
         iters, elapsed_us, ops_per_sec);
}

static void bench_channel(void) {
  long long cap = oo_cap_grant_thread();
  OoResS res = oo_channel_new(cap);
  CHECK(res.ok, "channel_new ok");
  if (!res.ok) return;

  long long slot = -1;
  sscanf(res.val.data, "ch:%lld", &slot);
  oo_str_release(res.val);
  CHECK(slot >= 0, "valid channel slot");

  const int msg_count = 2000;
  long long t0 = oo_monotonic_us();
  for (int i = 0; i < msg_count; i += 4) {
    for (int k = 0; k < 4; k++) {
      OoResS s = oo_channel_send(cap, slot, oo_str_lit("bench_msg"));
      if (!s.ok) fails++;
    }
    for (int k = 0; k < 4; k++) {
      OoResS r = oo_channel_recv(cap, slot);
      if (r.ok) oo_str_release(r.val);
      else fails++;
    }
  }
  long long elapsed_us = oo_monotonic_us() - t0;
  if (elapsed_us <= 0) elapsed_us = 1;
  long long msgs_per_sec = ((long long)msg_count * 1000000LL) / elapsed_us;
  OoResS d_res = oo_channel_destroy(cap, slot);
  oo_str_release(d_res.val);
  CHECK(msgs_per_sec >= 10000, "channel throughput >= 10,000 msg/s");
  printf("  perf: actor channel: %d msgs in %lld us (%lld msg/s)\n",
         msg_count, elapsed_us, msgs_per_sec);
}

static void bench_file_stat(void) {
  setenv("OODA_NO_JAIL", "1", 1);
  long long cap_fs = oo_cap_grant_fs();
  char path[256];
  snprintf(path, sizeof path, "/tmp/ooda_qa_stat_%d.tmp", (int)getpid());
  OoStr p = { path, (long long)strlen(path) };
  OoResV w = oo_write_file(cap_fs, p, oo_str_lit("PAYLOAD_TEST_DATA"));
  CHECK(w.ok, "write_file benchmark payload ok");

  const int iters = 1000;
  long long t0 = oo_monotonic_us();
  for (int i = 0; i < iters; i++) {
    if (!oo_path_exists(cap_fs, p)) fails++;
    if (oo_file_size(cap_fs, p) <= 0) fails++;
  }
  long long elapsed_us = oo_monotonic_us() - t0;
  if (elapsed_us <= 0) elapsed_us = 1;
  long long ops_per_sec = ((long long)iters * 2 * 1000000LL) / elapsed_us;
  oo_fs_remove_file(cap_fs, p);
  CHECK(ops_per_sec >= 5000, "file stat throughput >= 5,000 ops/s");
  printf("  perf: file stat/size: %d ops in %lld us (%lld ops/s)\n",
         iters * 2, elapsed_us, ops_per_sec);
}

int main(void) {
  alarm(30);
  bench_strings();
  bench_lists();
  bench_channel();
  bench_file_stat();

  if (fails == 0) {
    printf("OK\tperf_benchmark\tall throughput floors validated\n");
    return 0;
  }
  fprintf(stderr, "FAIL\tperf_benchmark\t%d failures\n", fails);
  return 1;
}
