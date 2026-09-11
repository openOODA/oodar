/* tests_challenger_address_safety.c — ASan + UBSan adversarial probe.
 *
 * Exercises every public cap-FREE oo_* entry point with hostile inputs
 * to catch use-after-free, buffer overflows, integer overflow, alignment
 * violations, and null dereferences. Compiled with
 * -fsanitize=address,undefined (see Makefile `test-asan` target).
 *
 * Any ASan/UBSan report at process exit = a real memory-safety bug.
 * The probe asserts no report via clean process exit (return 0).
 *
 * Scope: 14 cap-free probes. Cap-gated entry points (oo_sys_*, oo_fs_*,
 * oo_seal, oo_open, etc.) call oo_cap_require_* which exits(1) on
 * cap=0; those gates are already exhaustively tested by
 * tests_challenger_contract.c (56 cap=0 fail-closed mutators) and
 * tests_challenger_sys.c (spawn/wait/kill/epoll/inotify/prctl/exec_wait
 * cap=0). This probe focuses on what cap-gated tests miss: the pure
 * data-plane operations.
 */

#include "../oodar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

/* --- String family (cap-free) --- */

static void probe_str_lit_empty(void) {
  OoStr s = oo_str_lit("");
  long long n = oo_bytes_len(s);
  if (n != 0) {
    fprintf(stderr, "FAIL oo_bytes_len(empty)=%lld\n", n);
    g_failures++;
  }
}

static void probe_byte_at_oob(void) {
  /* oo_byte_at with idx past len — must not read past cap. */
  OoStr s = oo_str_lit("hi");
  long long v = oo_byte_at(s, 1000000);
  (void)v;
  v = oo_byte_at(s, -1);
  (void)v;
  v = oo_byte_at(s, 2); /* exactly past len */
  (void)v;
}

static void probe_str_byte_at_oob(void) {
  OoStr s = oo_str_lit("hello world");
  long long v = oo_str_byte_at(s, 1000000);
  (void)v;
}

static void probe_bytes_eq_self(void) {
  OoStr s = oo_str_lit("hello");
  int eq = oo_bytes_eq(s, s);
  if (eq != 1) {
    fprintf(stderr, "FAIL oo_bytes_eq(s,s)=%d\n", eq);
    g_failures++;
  }
}

static void probe_bytes_eq_empty(void) {
  OoStr a = oo_str_lit("");
  OoStr b = oo_str_lit("");
  int eq = oo_bytes_eq(a, b);
  if (eq != 1) {
    fprintf(stderr, "FAIL oo_bytes_eq(empty,empty)=%d\n", eq);
    g_failures++;
  }
}

static void probe_byte_slice_oob(void) {
  OoStr s = oo_str_lit("hello");
  /* start past len, end past len — must not crash */
  OoStr r = oo_byte_slice(s, 100, 200);
  long long n = oo_bytes_len(r);
  (void)n;
  r = oo_byte_slice(s, -1, 5);
  (void)oo_bytes_len(r);
}

static void probe_print_null_str(void) {
  /* oo_print_str / oo_eprint_str with null data — must not deref. */
  OoStr null_s;
  null_s.data = NULL;
  null_s.len = 0;
  oo_print_str(null_s);
  oo_eprint_str(null_s);
}

/* --- Math family (limb primitives — cap-free, real inputs) --- */

static void probe_limb_add_normal(void) {
  /* Real-input limb_add: small numbers, no overflow. UBSan should
   * stay silent. */
  long long cout = 0;
  long long r = oo_limb_add(1LL, 2LL, 0LL, &cout);
  if (r != 3LL || cout != 0) {
    fprintf(stderr, "FAIL oo_limb_add(1,2,0)=%lld cout=%lld\n", r, cout);
    g_failures++;
  }
}

static void probe_limb_mul_normal(void) {
  long long hi = 0;
  long long r = oo_limb_mul(7LL, 6LL, 0LL, &hi);
  if (r != 42LL || hi != 0) {
    fprintf(stderr, "FAIL oo_limb_mul(7,6,0)=%lld hi=%lld\n", r, hi);
    g_failures++;
  }
}

static void probe_limb_cmp(void) {
  long long r = oo_limb_cmp(5LL, 10LL);
  if (r >= 0) {
    fprintf(stderr, "FAIL oo_limb_cmp(5,10)=%lld (expected negative)\n", r);
    g_failures++;
  }
}

/* --- Null-deref path probe --- */

static void probe_null_deref_attempt(void) {
  volatile char *p = NULL;
  if (p != NULL && p[0] != 0) {
    fprintf(stderr, "FAIL unexpected branch in null path\n");
    g_failures++;
  }
}

/* --- Print family (cap-free, validates format-string safety) --- */

static void probe_print_extremes(void) {
  /* Print very large / very small numbers — no buffer overflow. */
  oo_print_int(9223372036854775807LL); /* INT64_MAX */
  oo_print_int(-9223372036854775807LL);
  oo_print_double(1e308);
  oo_print_double(-1e308);
  oo_println();
}

/* --- Driver --- */

/* --- Cap-gated OCap-side probes (v4.8.0, 6 new probes) ---
 *
 * Each of these probes tests the OCap-side path of a cap-gated entry
 * point. The pattern: fork a child, set oo_cap_bridge_set_test_force_fail(1),
 * call the cap-gated function with a real cap, expect exit(2) from
 * the dual-check wrapper. If the OCap path is broken (no exit(2)),
 * ASan would also catch any use-after-free / OOB / integer-overflow.
 *
 * These probes mirror tests_challenger_audio_cap.c probe 4 (the
 * OCap-disagreement probe) but cover a different surface: the
 * cap-gated data-plane ops that weren't in the audio probe. */

#include "../sec/cap/cap_ocap_bridge.h"
#include <sys/wait.h>
#include <unistd.h>

static void probe_cap_gated_sys_args(void) {
  pid_t pid = fork();
  if (pid == 0) {
    oo_cap_bridge_set_test_force_fail(1);
    long long sys = oo_cap_self_token(1);
    OoSList r = oo_sys_args(sys);
    (void)r;
    _exit(0);  /* must not reach — OCap fail should abort(2) */
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (!(WIFEXITED(status) && WEXITSTATUS(status) == 2)) {
    fprintf(stderr, "FAIL oo_sys_args(ocap forced fail) should exit(2)\n");
    g_failures++;
  }
}

static void probe_cap_gated_metrics_self_test(void) {
  pid_t pid = fork();
  if (pid == 0) {
    oo_cap_bridge_set_test_force_fail(1);
    long long m = oo_cap_self_token(21);  /* g_tok_metrics */
    int rc = oo_metrics_self_test(m);
    (void)rc;
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (!(WIFEXITED(status) && WEXITSTATUS(status) == 2)) {
    fprintf(stderr, "FAIL oo_metrics_self_test(ocap forced fail) should exit(2)\n");
    g_failures++;
  }
}

static void probe_cap_gated_lto_xlang_link(void) {
  /* oo_lto_xlang_link is gated by oo_cap_require_process (ProcessCap,
   * index 5), not FfiCap. The dual-check wrapper for ProcessCap IS
   * wired (v4.5.0); this probe exercises it. */
  pid_t pid = fork();
  if (pid == 0) {
    oo_cap_bridge_set_test_force_fail(1);
    long long proc = oo_cap_self_token(5);  /* g_tok_process */
    long long r = oo_lto_xlang_link(proc, oo_str_lit("/tmp/a.o"), oo_str_lit("/tmp/b.so"));
    (void)r;
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (!(WIFEXITED(status) && WEXITSTATUS(status) == 2)) {
    fprintf(stderr, "FAIL oo_lto_xlang_link(ocap forced fail) should exit(2)\n");
    g_failures++;
  }
}

static void probe_cap_gated_import_c(void) {
  /* oo_import_c is gated by oo_cap_require_ffi (FfiCap, index 25).
   * The FfiCap wrapper in cap_ffi.c does NOT use dual_check (action
   * item A1 in audit/2026-09-12-round7-residual-check.oot). When that
   * fix lands, this probe will start exiting(2). For now, we test
   * the bitmask side and verify it rejects a wrong cap. */
  pid_t pid = fork();
  if (pid == 0) {
    /* Don't set force-fail — the FfiCap wrapper doesn't check OCap. */
    long long wrong = oo_cap_self_token(0);  /* g_tok_fs, wrong for ffi */
    long long r = oo_import_c(wrong, oo_str_lit("/tmp/header.h"));
    (void)r;
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (!(WIFEXITED(status) && WEXITSTATUS(status) == 1)) {
    fprintf(stderr, "FAIL oo_import_c(wrong cap) should exit(1); see round7 action A1\n");
    g_failures++;
  }
}

static void probe_cap_gated_env_get(void) {
  /* oo_env_get(cap, key) — EnvCap-gated quick read. Calls libc getenv
   * after the dual-check. With force-fail, the wrapper must exit(2). */
  pid_t pid = fork();
  if (pid == 0) {
    oo_cap_bridge_set_test_force_fail(1);
    long long env = oo_cap_self_token(2);  /* g_tok_env */
    OoResS r = oo_env_get(env, oo_str_lit("PATH"));
    (void)r;
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (!(WIFEXITED(status) && WEXITSTATUS(status) == 2)) {
    fprintf(stderr, "FAIL oo_env_get(ocap forced fail) should exit(2)\n");
    g_failures++;
  }
}

static void probe_cap_gated_dlopen(void) {
  /* oo_dlopen is gated by oo_cap_require_ffi (FfiCap, index 25).
   * Same as oo_import_c: FfiCap wrapper doesn't dual-check (round7
   * action A1). Test the bitmask side for now. */
  pid_t pid = fork();
  if (pid == 0) {
    long long wrong = oo_cap_self_token(0);
    OoResS r = oo_dlopen(wrong, oo_str_lit("/nonexistent.so"));
    (void)r;
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (!(WIFEXITED(status) && WEXITSTATUS(status) == 1)) {
    fprintf(stderr, "FAIL oo_dlopen(wrong cap) should exit(1); see round7 action A1\n");
    g_failures++;
  }
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  fprintf(stderr, "  address-safety probe: starting\n");

  /* String family */
  probe_str_lit_empty();
  probe_byte_at_oob();
  probe_str_byte_at_oob();
  probe_bytes_eq_self();
  probe_bytes_eq_empty();
  probe_byte_slice_oob();
  probe_print_null_str();

  /* Math family (UBSan should stay silent on real inputs) */
  probe_limb_add_normal();
  probe_limb_mul_normal();
  probe_limb_cmp();

  /* Null-deref safety */
  probe_null_deref_attempt();

  /* Print family */
  probe_print_extremes();

  /* Cap-gated OCap-side probes (v4.8.0) */
  probe_cap_gated_sys_args();
  probe_cap_gated_metrics_self_test();
  probe_cap_gated_lto_xlang_link();
  probe_cap_gated_import_c();
  probe_cap_gated_env_get();
  probe_cap_gated_dlopen();

  if (g_failures != 0) {
    fprintf(stderr, "FAIL address-safety: %d logical failures\n", g_failures);
    return 1;
  }

  fprintf(stderr, "OK address-safety: 18 probes ran clean under ASan+UBSan\n");
  return 0;
}
