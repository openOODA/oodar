/* qa/tests_challenger_adversarial_boundary.c — Negative-trust & boundary probes.
 * Validates zero-length files, adversarial strings & embedded NUL paths, OOB
 * indexing across all list types, ungranted (cap=0) / forged / cross-domain
 * capability enforcement, and oversized channel payload clamping.
 * Exit codes: 0 = PASS, 1 = FAIL. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include "../oodar.h"
#include "../types.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { fprintf(stderr, "FAIL\tboundary\t%s\n", msg); fails++; } \
} while (0)

static void test_zero_length_file(void) {
  setenv("OODA_NO_JAIL", "1", 1);
  long long cap_fs = oo_cap_grant_fs();
  char path[256];
  snprintf(path, sizeof path, "/tmp/ooda_qa_zero_%d.tmp", (int)getpid());
  OoStr p = { path, (long long)strlen(path) };

  OoResV w = oo_write_file(cap_fs, p, (OoStr){NULL, 0});
  CHECK(w.ok, "write_file 0 bytes succeeded");
  CHECK(oo_path_exists(cap_fs, p) == 1, "path_exists on 0-byte file is 1");
  CHECK(oo_file_size(cap_fs, p) == 0, "file_size on 0-byte file is 0");

  OoResS r = oo_read_file(cap_fs, p);
  CHECK(r.ok, "read_file 0 bytes succeeded");
  CHECK(r.val.len == 0, "read_file 0 bytes length is 0");
  if (r.ok) oo_str_release(r.val);

  oo_fs_remove_file(cap_fs, p);
  CHECK(oo_path_exists(cap_fs, p) == 0, "path_exists after remove is 0");
}

static void test_adversarial_strings_and_paths(void) {
  setenv("OODA_NO_JAIL", "1", 1);
  long long cap_fs = oo_cap_grant_fs();

  OoStr rep_neg = oo_str_repeat(oo_str_lit("xyz"), -5);
  CHECK(rep_neg.len == 0, "oo_str_repeat negative count returns len 0");
  oo_str_release(rep_neg);
  OoStr rep_zero = oo_str_repeat(oo_str_lit("xyz"), 0);
  CHECK(rep_zero.len == 0, "oo_str_repeat zero count returns len 0");
  oo_str_release(rep_zero);
  OoStr rep_big = oo_str_repeat(oo_str_lit("a"), 100000);
  CHECK(rep_big.len == 1024, "oo_str_repeat clamps huge count to 1024");
  oo_str_release(rep_big);

  OoStr neg_str = { "abcdef", -10 };
  CHECK(oo_str_contains(neg_str, oo_str_lit("a")) == 0, "contains on negative-len is 0");
  CHECK(oo_str_starts_with(neg_str, oo_str_lit("a")) == 0, "starts_with on negative-len is 0");
  CHECK(oo_str_ends_with(neg_str, oo_str_lit("f")) == 0, "ends_with on negative-len is 0");
  CHECK(oo_str_index_of(neg_str, oo_str_lit("a")) == -1, "index_of on negative-len is -1");

  OoStr base = oo_str_lit("hello_boundary");
  OoStr sl1 = oo_byte_slice(base, -100, 5);
  CHECK(sl1.len == 5 && memcmp(sl1.data, "hello", 5) == 0, "slice negative start clamps to 0");
  oo_str_release(sl1);
  OoStr sl2 = oo_byte_slice(base, 5, 2);
  CHECK(sl2.len == 0, "slice inverted start > end returns empty");
  oo_str_release(sl2);
  OoStr sl3 = oo_byte_slice(base, 6, 9999);
  CHECK(sl3.len == 8 && memcmp(sl3.data, "boundary", 8) == 0, "slice oversized end clamps to len");
  oo_str_release(sl3);

  CHECK(oo_byte_at(base, -1) == -1, "oo_byte_at negative index returns -1");
  CHECK(oo_byte_at(base, base.len) == -1, "oo_byte_at len index returns -1");
  CHECK(oo_byte_at(base, 99999) == -1, "oo_byte_at huge index returns -1");
  CHECK(oo_byte_at((OoStr){NULL, 0}, 0) == -1, "oo_byte_at null data returns -1");

  /* Adversarial paths: embedded NUL, NULL pointer, oversized */
  char bad_nul[] = "/tmp/bad\0hidden.tmp";
  OoResS r_nul = oo_read_file(cap_fs, (OoStr){bad_nul, sizeof(bad_nul) - 1});
  CHECK(!r_nul.ok, "read_file with embedded NUL fails closed");
  OoResS r_null = oo_read_file(cap_fs, (OoStr){NULL, 0});
  CHECK(!r_null.ok, "read_file with NULL path fails closed");
  char huge_p[PATH_MAX + 64]; memset(huge_p, 'x', sizeof huge_p);
  OoResS r_huge = oo_read_file(cap_fs, (OoStr){huge_p, (long long)sizeof(huge_p)});
  CHECK(!r_huge.ok, "read_file with oversized path fails closed");
}

static void test_adversarial_bytes(void) {
  OoIList bl = oo_bytes_new();
  OoIList t1 = bl; bl = oo_bytes_push(bl, -999); oo_ilist_release(t1);
  OoIList t2 = bl; bl = oo_bytes_push(bl, 9999); oo_ilist_release(t2);
  CHECK(oo_bytes_get(bl, 0) == 0, "bytes_push negative clamped to 0");
  CHECK(oo_bytes_get(bl, 1) == 255, "bytes_push >255 clamped to 255");
  CHECK(oo_bytes_get(bl, -1) == -1, "bytes_get negative index returns -1");
  CHECK(oo_bytes_get(bl, 2) == -1, "bytes_get out-of-bounds returns -1");
  oo_ilist_release(bl);
}

static void test_oob_indexing_fail_closed(void) {
  pid_t p1 = fork();
  if (p1 == 0) {
    alarm(3);
    OoIList l = oo_ilist_push(oo_ilist_new(), 42);
    oo_ilist_get(l, 10);
    _exit(0);
  }
  int st1 = 0; waitpid(p1, &st1, 0);
  CHECK(WIFEXITED(st1) && WEXITSTATUS(st1) == 1, "oo_ilist_get OOB exits(1)");

  pid_t p2 = fork();
  if (p2 == 0) {
    alarm(3);
    OoFList fl = oo_flist_push(oo_flist_new(), 3.14);
    oo_flist_get(fl, 10);
    _exit(0);
  }
  int st2 = 0; waitpid(p2, &st2, 0);
  CHECK(WIFEXITED(st2) && WEXITSTATUS(st2) == 1, "oo_flist_get OOB exits(1)");

  pid_t p3 = fork();
  if (p3 == 0) {
    alarm(3);
    OoSList sl = oo_slist_push(oo_slist_new(), oo_str_lit("hi"));
    oo_slist_get(sl, 10);
    _exit(0);
  }
  int st3 = 0; waitpid(p3, &st3, 0);
  CHECK(WIFEXITED(st3) && WEXITSTATUS(st3) == 1, "oo_slist_get OOB exits(1)");
}

static void test_ungranted_and_forged_caps_fail_closed(void) {
  pid_t p1 = fork();
  if (p1 == 0) {
    alarm(3);
    oo_read_file(0, oo_str_lit("/etc/passwd")); /* ungranted cap=0 */
    _exit(0);
  }
  int st1 = 0; waitpid(p1, &st1, 0);
  CHECK(WIFEXITED(st1) && WEXITSTATUS(st1) == 1, "cap=0 exits(1) fail-closed");

  pid_t p2 = fork();
  if (p2 == 0) {
    alarm(3);
    oo_read_file(0xDEADBEEFCAFE1234LL, oo_str_lit("/etc/passwd")); /* forged token */
    _exit(0);
  }
  int st2 = 0; waitpid(p2, &st2, 0);
  CHECK(WIFEXITED(st2) && WEXITSTATUS(st2) == 1, "forged cap exits(1) fail-closed");

  pid_t p3 = fork();
  if (p3 == 0) {
    alarm(3);
    long long thread_cap = oo_cap_grant_thread();
    oo_read_file(thread_cap, oo_str_lit("/etc/passwd")); /* wrong domain */
    _exit(0);
  }
  int st3 = 0; waitpid(p3, &st3, 0);
  CHECK(WIFEXITED(st3) && WEXITSTATUS(st3) == 1, "wrong cap domain exits(1) fail-closed");

  pid_t p4 = fork();
  if (p4 == 0) {
    alarm(3);
    oo_channel_new(0); /* cap=0 on channel */
    _exit(0);
  }
  int st4 = 0; waitpid(p4, &st4, 0);
  CHECK(WIFEXITED(st4) && WEXITSTATUS(st4) == 1, "channel_new cap=0 exits(1) fail-closed");
}

static void test_oversized_channel_payload(void) {
  long long cap = oo_cap_grant_thread();
  OoResS ch_res = oo_channel_new(cap);
  CHECK(ch_res.ok, "channel_new ok for oversized test");
  long long slot = -1;
  sscanf(ch_res.val.data, "ch:%lld", &slot);
  oo_str_release(ch_res.val);

  /* Send payload > 1MB: must clamp to 1MB (1LL << 20 = 1048576) */
  size_t huge_len = (1024 * 1024) + 65536;
  char *huge_buf = oo_str_alloc_payload(huge_len);
  memset(huge_buf, 'K', huge_len);
  OoStr huge_msg = { huge_buf, (long long)huge_len };

  OoResS s = oo_channel_send(cap, slot, huge_msg);
  CHECK(s.ok, "channel_send oversized msg accepted");

  OoResS r = oo_channel_recv(cap, slot);
  CHECK(r.ok, "channel_recv oversized msg received");
  CHECK(r.val.len == (1LL << 20), "oversized msg clamped to 1MB ceiling");
  if (r.ok) oo_str_release(r.val);

  oo_str_release(huge_msg);
  OoResS d = oo_channel_destroy(cap, slot);
  oo_str_release(d.val);
}

int main(void) {
  alarm(30);
  test_zero_length_file();
  test_adversarial_strings_and_paths();
  test_adversarial_bytes();
  test_oob_indexing_fail_closed();
  test_ungranted_and_forged_caps_fail_closed();
  test_oversized_channel_payload();

  if (fails == 0) {
    printf("OK\tboundary\tzero-files+strings+OOB(I/F/S)+cap0/forged+oversized pass\n");
    return 0;
  }
  fprintf(stderr, "FAIL\tboundary\t%d failures\n", fails);
  return 1;
}
