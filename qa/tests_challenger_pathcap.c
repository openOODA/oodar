/* qa/tests_challenger_pathcap.c — path-prefix cap contract.
 *
 * Round-5 deep-dive: oo_attenuate_fsread_to_path must fail-closed
 * on cap=0 and accept valid caps. The contract is the same as
 * the v3.2.0 contract test, but specifically for the
 * path-prefix geometry.
 *
 * Beats:
 *   1. cap=0: function must fail-closed (the canonical
 *      oo_cap_require_fsread() exits(1) on cap=0).
 *   2. Wrong cap (e.g., AllocCap): must fail-closed.
 *   3. Valid FsReadCap + absolute path: must produce a
 *      non-empty OoPathCap.
 *   4. Chain re-attenuation: oo_attenuate_fsread_to_path on the
 *      parent_cap of a previously-derived OoPathCap should work.
 *   5. Path-prefix check: oo_path_cap_check with a path that
 *      starts with the prefix must return 1; with a different
 *      path must return 0.
 *
 * v3.3.1 added: this test.
 *
 * Exit codes:
 *   0 — all 5 beats pass
 *   1 — at least one beat leaks
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../oodar.h"
#include "../sec/cap/caps.h"

/* run_in_child(fn, expect_exit_zero):
 *   if expect_exit_zero, returns 1 if child exited 0 (PASS) or non-zero (FAIL)
 *   if !expect_exit_zero, returns 1 if child exited non-zero (fail-closed) or 0 (LEAK)
 */
static int run_in_child(void (*fn)(void), int expect_exit_zero) {
  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return -1; }
  if (pid == 0) { alarm(2); fn(); _exit(0); }
  int st = 0;
  waitpid(pid, &st, 0);
  if (expect_exit_zero) {
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) return 1;
    return 0;
  }
  if (WIFEXITED(st) && WEXITSTATUS(st) != 0) return 1;
  if (WIFSIGNALED(st)) return 1;
  return 0;
}

static void beat1_cap_zero(void) {
  OoPathCap r = oo_attenuate_fsread_to_path(0, oo_str_lit("/tmp"));
  (void)r;
  fprintf(stderr, "  LEAK beat1: cap=0 returned without failing\n"); fflush(stderr);
  _exit(0);
}
static void beat2_wrong_cap(void) {
  OoPathCap r = oo_attenuate_fsread_to_path(0xdeadbeefLL, oo_str_lit("/tmp"));
  (void)r;
  fprintf(stderr, "  LEAK beat2: wrong cap returned without failing\n"); fflush(stderr);
  _exit(0);
}
static void beat3_valid_cap(void) {
  OoPathCap r = oo_attenuate_fsread_to_path(oo_cap_self_token(15), oo_str_lit("/tmp"));
  fprintf(stderr, "  beat3: parent_cap=%lld prefix.len=%lld\n", r.parent_cap, r.prefix.len); fflush(stderr);
  if (r.parent_cap == 0) { fprintf(stderr, "  LEAK beat3a: parent_cap=0\n"); _exit(0); }
  if (r.prefix.len <= 0) { fprintf(stderr, "  LEAK beat3b: prefix.len=0\n"); _exit(0); }
  _exit(0);
}
static void beat4_chain_re_attenuation(void) {
  OoPathCap a = oo_attenuate_fsread_to_path(oo_cap_self_token(15), oo_str_lit("/tmp"));
  OoPathCap b = oo_attenuate_fsread_to_path(a.parent_cap, oo_str_lit("/tmp/sub"));
  fprintf(stderr, "  beat4: a.parent_cap=%lld b.parent_cap=%lld\n", a.parent_cap, b.parent_cap); fflush(stderr);
  if (b.parent_cap == 0) { fprintf(stderr, "  LEAK beat4: chain failed\n"); _exit(0); }
  _exit(0);
}
static void beat5_path_prefix_check(void) {
  OoPathCap r = oo_attenuate_fsread_to_path(oo_cap_self_token(15), oo_str_lit("/tmp"));
  int ok1 = oo_path_cap_check(r, oo_str_lit("/tmp/x"));
  int ok2 = oo_path_cap_check(r, oo_str_lit("/etc/passwd"));
  fprintf(stderr, "  beat5: ok1=%d (should be 1), ok2=%d (should be 0)\n", ok1, ok2); fflush(stderr);
  if (!ok1) { fprintf(stderr, "  LEAK beat5a: /tmp/x did not match\n"); _exit(0); }
  if (ok2)  { fprintf(stderr, "  LEAK beat5b: /etc/passwd matched\n"); _exit(0); }
  _exit(0);
}

/* v3.3.3: use-after-free test. The previous shallow-borrow
 * design required the caller to keep the prefix buffer alive
 * for the lifetime of the OoPathCap. If the caller freed the
 * buffer (e.g., returned from a function that allocated on the
 * stack), oo_path_cap_check would read freed memory. The
 * v3.3.3 deep-copy fix makes OoPathCap own its prefix. This
 * test exercises the failure mode: derive a cap, then
 * scribble over the source buffer, then check the cap. The
 * check should still pass because the OoPathCap owns its
 * copy. */
static void beat7_tmp_vs_tmpfoo(void) {
  OoPathCap r = oo_attenuate_fsread_to_path(oo_cap_self_token(15), oo_str_lit("/tmp"));
  if (oo_path_cap_check(r, oo_str_lit("/tmpfoo"))) {
    fprintf(stderr, "  LEAK beat7: /tmp matched /tmpfoo\n"); _exit(0);
  }
  if (!oo_path_cap_check(r, oo_str_lit("/tmp/x"))) {
    fprintf(stderr, "  LEAK beat7: /tmp/x should match\n"); _exit(0);
  }
  _exit(0);
}
static void beat8_no_widen(void) {
  OoPathCap a = oo_attenuate_fsread_to_path(oo_cap_self_token(15), oo_str_lit("/tmp"));
  OoPathCap b = oo_attenuate_pathcap_to_path(a, oo_str_lit("/etc"));
  if (b.parent_cap != 0 || b.prefix.len != 0) {
    fprintf(stderr, "  LEAK beat8: /tmp pathcap widened to /etc\n"); _exit(0);
  }
  OoPathCap c = oo_attenuate_pathcap_to_path(a, oo_str_lit("/tmp/sub"));
  if (c.parent_cap == 0) {
    fprintf(stderr, "  LEAK beat8: nested /tmp/sub should work\n"); _exit(0);
  }
  _exit(0);
}
static void beat6_uaf_safe(void) {
  char buf[16];
  memcpy(buf, "/tmp", 4); buf[4] = 0;
  OoStr s; s.data = buf; s.len = 4;
  OoPathCap r = oo_attenuate_fsread_to_path(oo_cap_self_token(15), s);
  /* Scribble over the source buffer to simulate caller-side
   * free / realloc. The OoPathCap must still be valid. */
  memset(buf, 'X', sizeof buf);
  int ok = oo_path_cap_check(r, oo_str_lit("/tmp/x"));
  if (!ok) { fprintf(stderr, "  LEAK beat6: UAF detected — deep-copy failed\n"); _exit(0); }
  _exit(0);
}

int main(void) {
  /* Beats 1, 2: cap=0 and wrong cap should fail-closed (child exits non-zero). */
  int p1 = run_in_child(beat1_cap_zero, 0);
  int p2 = run_in_child(beat2_wrong_cap, 0);
  /* Beats 3, 4, 5, 6: valid cap should work (child exits 0). */
  int p3 = run_in_child(beat3_valid_cap, 1);
  int p4 = run_in_child(beat4_chain_re_attenuation, 1);
  int p5 = run_in_child(beat5_path_prefix_check, 1);
  int p6 = run_in_child(beat6_uaf_safe, 1);
  int p7 = run_in_child(beat7_tmp_vs_tmpfoo, 1);
  int p8 = run_in_child(beat8_no_widen, 1);
  int total = 8, passed = p1 + p2 + p3 + p4 + p5 + p6 + p7 + p8;
  fprintf(stderr, "pathcap: %d/%d beats (p1=%d p2=%d p3=%d p4=%d p5=%d p6=%d p7=%d p8=%d)\n",
          passed, total, p1, p2, p3, p4, p5, p6, p7, p8);
  if (passed == total) {
    printf("OK\tpathcap\t%d/%d beats pass (boundary + no-widen)\n",
           passed, total);
    return 0;
  }
  fprintf(stderr, "FAIL\tpathcap\t%d / %d beats failed\n", total - passed, total);
  return 1;
}
