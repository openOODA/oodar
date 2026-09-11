/* tests_challenger_ocap_bridge.c — Hostile probe for the OCap bridge.
 *
 * Phase 1 verification: the OCap bridge (oodar/sec/cap/cap_ocap_bridge.c
 * + the oodac-emitted C from std/sec/capability/ocap_to_oodar.oo) must
 * give bit-for-bit equivalence with the bitmask cap-system on the
 * documented rights-mask expectations.
 *
 * Phase 2 verification: the dual-check wrapper for oo_cap_require_fs
 * must abort when the bitmask path passes but the OCap path fails.
 * Tested by forking: parent observes the child's exit code, expects
 * non-zero. The child uses oo_cap_bridge_set_test_force_fail to force
 * the next OCap check to fail.
 *
 * Probe matrix:
 *   1. cap=0 always returns 0 (fail-closed on absence).
 *   2. Forge attempts (cap=0xFFFFFFFFFFFFFFFF) return 0 (not a real token).
 *   3. Real tokens (via oo_cap_self_token) return the documented rights
 *      mask for their language token (NORTHSTAR §1.4 mapping).
 *   4. Subset rule: granting a rights mask M and checking M & required
 *      == required gives 1; checking M & non_subset gives 0.
 *   5. Disagreement: oo_cap_require_fs(real_fs_cap) with OCap forced
 *      to fail must abort with non-zero exit code (the tripwire).
 *
 * Exit codes: 0 = all probes pass; 1 = at least one probe failed.
 */

#include "../oodar.h"
#include "../sec/cap/cap_ocap_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_failures = 0;

#define ASSERT(cond, msg)                                                   \
  do {                                                                      \
    if (!(cond)) {                                                          \
      fprintf(stderr, "FAIL ocap_bridge: %s\n", msg);                       \
      g_failures++;                                                         \
    }                                                                       \
  } while (0)

/* --- Probe 1: cap=0 is fail-closed --- */
static void probe_cap_zero(void) {
  /* oo_cap_check_with_ocap is defined in cap_ocap_bridge.c; the
   * prototype lives in oodar.h (added in this commit). */
  extern int oo_cap_check_with_ocap(long long cap, long long required_rights);

  int r = oo_cap_check_with_ocap(0LL, 1LL);
  ASSERT(r == 0, "oo_cap_check_with_ocap(0, read) returned non-zero");
}

/* --- Probe 2: forge attempts --- */
static void probe_forge_attempt(void) {
  extern int oo_cap_check_with_ocap(long long cap, long long required_rights);
  /* Random forge: cap=-1 must not match any real token. */
  int r = oo_cap_check_with_ocap(-1LL, 1LL);
  ASSERT(r == 0, "oo_cap_check_with_ocap(-1, read) returned non-zero (forge accepted)");
  r = oo_cap_check_with_ocap(0xDEADBEEFCAFEBABEULL, 31LL);
  ASSERT(r == 0, "oo_cap_check_with_ocap(0xDEADBEEF, all-rights) returned non-zero (forge accepted)");
}

/* --- Probe 3: real tokens return the documented rights mask --- */
static void probe_real_tokens(void) {
  /* oo_cap_ocap_rights_at(which) returns the rights mask for the
   * substrate cap at index `which` (0..25). Per the SUBSTRATE_TO_LANGUAGE
   * mapping in cap_ocap_bridge.c:
   *   index 0  = g_tok_fs     -> FsCap     -> 31 (full FS)
   *   index 1  = g_tok_sys    -> SysCap    -> 7  (read+write+execute)
   *   index 2  = g_tok_env    -> EnvCap    -> 1  (read)
   *   index 3  = g_tok_net    -> NetCap    -> 3  (read+write)
   *   index 15 = g_tok_fsread -> FsReadCap -> 1  (read)
   *   index 16 = g_tok_fswrite-> FsWriteCap-> 3  (read+write)
   *   index 22 = g_tok_alloc  -> AllocCap  -> 3  (read+write)
   *   index 25 = g_tok_ffi    -> FfiCap    -> 7  (read+write+execute)
   */
  extern long long oo_cap_ocap_rights_at(int which);

  long long r;

  r = oo_cap_ocap_rights_at(0);   /* FsCap */
  ASSERT(r == 31, "g_tok_fs rights mask != 31");

  r = oo_cap_ocap_rights_at(1);   /* SysCap */
  ASSERT(r == 7, "g_tok_sys rights mask != 7");

  r = oo_cap_ocap_rights_at(2);   /* EnvCap */
  ASSERT(r == 1, "g_tok_env rights mask != 1");

  r = oo_cap_ocap_rights_at(3);   /* NetCap */
  ASSERT(r == 3, "g_tok_net rights mask != 3");

  r = oo_cap_ocap_rights_at(15);  /* FsReadCap */
  ASSERT(r == 1, "g_tok_fsread rights mask != 1");

  r = oo_cap_ocap_rights_at(16);  /* FsWriteCap */
  ASSERT(r == 3, "g_tok_fswrite rights mask != 3");

  r = oo_cap_ocap_rights_at(22);  /* AllocCap */
  ASSERT(r == 3, "g_tok_alloc rights mask != 3");

  r = oo_cap_ocap_rights_at(25);  /* FfiCap */
  ASSERT(r == 7, "g_tok_ffi rights mask != 7");
}

/* --- Probe 4: subset rule --- */
static void probe_subset_rule(void) {
  extern int oo_cap_check_with_ocap(long long cap, long long required_rights);

  /* oo_cap_self_token(0) = g_tok_fs = FsCap = 31. All subset
   * checks should pass for the full rights. */
  long long fs = oo_cap_self_token(0);
  ASSERT(oo_cap_check_with_ocap(fs, 1) == 1, "FsCap should have read");
  ASSERT(oo_cap_check_with_ocap(fs, 2) == 1, "FsCap should have write");
  ASSERT(oo_cap_check_with_ocap(fs, 4) == 1, "FsCap should have execute");
  ASSERT(oo_cap_check_with_ocap(fs, 8) == 1, "FsCap should have delegate");
  ASSERT(oo_cap_check_with_ocap(fs, 16) == 1, "FsCap should have revoke");
  ASSERT(oo_cap_check_with_ocap(fs, 31) == 1, "FsCap should have all rights");

  /* oo_cap_self_token(2) = g_tok_env = EnvCap = 1. Only read. */
  long long env = oo_cap_self_token(2);
  ASSERT(oo_cap_check_with_ocap(env, 1) == 1, "EnvCap should have read");
  ASSERT(oo_cap_check_with_ocap(env, 2) == 0, "EnvCap should NOT have write");
  ASSERT(oo_cap_check_with_ocap(env, 4) == 0, "EnvCap should NOT have execute");
  ASSERT(oo_cap_check_with_ocap(env, 31) == 0, "EnvCap should NOT have all rights");

  /* Attenuation: child_rights ⊆ parent_rights. If a child asks for
   * bits the parent doesn't have, the bridge refuses. */
  ASSERT(oo_cap_check_with_ocap(env, 2 | 4) == 0,
         "EnvCap should refuse write|execute");
}

/* --- Probe 5: dual-check disagreement fires abort (Phase 2) ---
 * oo_cap_require_fs(real_fs_cap, ...) should succeed normally.
 * But when the OCap path is forced to fail (via the test hook),
 * the dual-check wrapper must abort with non-zero exit. We test
 * this by forking: the child sets the force-fail flag, then calls
 * the wrapper. The parent waits and checks the child's exit code.
 *
 * We also test the success case: a clean child process calls
 * oo_cap_require_fs with the real cap and exits 0 normally — this
 * proves the dual-check doesn't break the existing happy path. */
static void probe_dual_check_disagreement(void) {
  extern void oo_cap_require_fs(long long got, const char *op);

  /* Sub-test 5a: happy path. Child calls oo_cap_require_fs with the
   * real fs cap; must exit 0. */
  pid_t pid_ok = fork();
  if (pid_ok == 0) {
    long long fs = oo_cap_self_token(0);
    oo_cap_require_fs(fs, "test_ok");
    _exit(0);
  }
  int status_ok = 0;
  waitpid(pid_ok, &status_ok, 0);
  ASSERT(WIFEXITED(status_ok) && WEXITSTATUS(status_ok) == 0,
         "oo_cap_require_fs(real fs cap) should succeed; child exited non-zero");

  /* Sub-test 5b: disagreement. Child forces the next OCap check to
   * fail, then calls oo_cap_require_fs with the real fs cap. The
   * bitmask path will pass (real cap), but the OCap path will fail
   * (forced), so the wrapper must abort with exit(2). */
  pid_t pid_bad = fork();
  if (pid_bad == 0) {
    oo_cap_bridge_set_test_force_fail(1);
    long long fs = oo_cap_self_token(0);
    oo_cap_require_fs(fs, "test_disagree");
    _exit(0);  /* should never reach here */
  }
  int status_bad = 0;
  waitpid(pid_bad, &status_bad, 0);
  ASSERT(WIFEXITED(status_bad) && WEXITSTATUS(status_bad) == 2,
         "oo_cap_require_fs(real fs cap, ocap forced fail) should exit(2); child exited differently");
}

/* --- Driver --- */
int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  fprintf(stderr, "  ocap-bridge probe: starting\n");

  probe_cap_zero();
  probe_forge_attempt();
  probe_real_tokens();
  probe_subset_rule();
  probe_dual_check_disagreement();

  if (g_failures != 0) {
    fprintf(stderr, "FAIL ocap-bridge: %d failures\n", g_failures);
    return 1;
  }
  fprintf(stderr, "OK ocap-bridge: 5 probes passed (cap=0, forge, real-tokens, subset, dual-disagree)\n");
  return 0;
}
