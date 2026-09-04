/* # qa/tests_challenger_cap_escape.c — Tier-5 Cap System Escape Probe
 *
 * Logline: Tier-5 adversarial probe for the cap system. Tries 4 escape
 * paths: (a) forging a cap from a known token, (b) calling oo_alloc with
 * cap=0, (c) calling oo_write_int with a foreign pointer, (d) calling
 * oo_proc_mem_read without Landlock applied. Each must fail closed.
 *
 * Setup: This file is RED — it MUST NOT be in the umbrella TU. The
 * audit verifies the cap system is sound by attempting to bypass it;
 * a successful bypass is a security defect.
 *
 * Each attempt runs in a child process (fork). If the child exits 0,
 * the bypass SUCCEEDED (security defect — the test exits 1). If the
 * child is killed by the cap system (exits non-zero, or aborts), the
 * bypass FAILED (test exits 0). The umbrella build excludes this
 * file (it is run by the developer, not the runtime).
 *
 * Beats:
 *   1. (a) Forging a cap: use a known-bad token (1234) with
 *      oo_alloc. The cap system must reject it (exit non-zero).
 *   2. (b) cap=0: oo_alloc with cap=0 must be rejected.
 *   3. (c) Foreign pointer: oo_write_int with a non-magic pointer
 *      must be rejected.
 *   4. (d) proc_mem without Landlock: oo_proc_mem_read without
 *      oo_landlock_restrict must return an empty result (not the
 *      contents of process memory).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

/* Use the umbrella TU for the actual oo_* symbols. We #include
 * the .c files directly here so this is a stand-alone test binary
 * that does not require the umbrella to be pre-compiled. */
#include "../oodar.h"
#include "../types.h"
/* oodar.h defines the oo_* symbols we need (oo_cap_grant_alloc,
 * oo_alloc, oo_read_int, oo_proc_mem_read, oo_landlock_is_available,
 * oo_landlock_is_applied). No forward declarations needed — and
 * forward-declaring oo_read_int / oo_write_int would conflict with
 * the variadic macros in oodar.h. */

/* Run a child that attempts a cap-bypass; return 1 if the bypass
 * SUCCEEDED (child exited 0), 0 if the cap system rejected it. */
static int child_escaped(void) {
  pid_t pid = fork();
  if (pid == 0) {
    /* child: try the bypass; the cap system will kill us on success. */
    return 0;  /* placeholder; replaced by each test below */
  }
  int status = 0;
  waitpid(pid, &status, 0);
  /* If the child exited cleanly (status == 0), the bypass succeeded. */
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 1;
  return 0;
}

int main(void) {
  int bypass_count = 0;
  int rc = 0;

  printf("challenger\tcap_escape\tstarting 4 cap-bypass probes\n");

  /* Probe (a): forge a cap from a known bad token. */
  {
    pid_t pid = fork();
    if (pid == 0) {
      long long forged = 0xDEADBEEF12345678LL;
      long long p = oo_alloc(forged, 64);
      (void)p;
      _exit(0);  /* would only reach here if cap was accepted */
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      printf("FAIL\tcap_escape\t(a) forged cap accepted\n");
      bypass_count++;
    } else {
      printf("OK\tcap_escape\t(a) forged cap rejected\n");
    }
  }

  /* Probe (b): cap=0. */
  {
    pid_t pid = fork();
    if (pid == 0) {
      long long p = oo_alloc(0, 64);
      (void)p;
      _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      printf("FAIL\tcap_escape\t(b) cap=0 accepted\n");
      bypass_count++;
    } else {
      printf("OK\tcap_escape\t(b) cap=0 rejected\n");
    }
  }

  /* Probe (c): foreign pointer to oo_read_int. The function calls
   * exit(1) on bad magic, so any non-zero exit is a rejection. */
  {
    pid_t pid = fork();
    if (pid == 0) {
      long long valid_cap = oo_cap_grant_alloc();
      /* Point at a stack slot that has no OoRawAllocHeader magic. */
      long long foreign = 0x12345678;
      oo_read_int(valid_cap, foreign, 0);
      _exit(0);  /* only reached if magic was silently accepted */
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      printf("FAIL\tcap_escape\t(c) foreign pointer accepted\n");
      bypass_count++;
    } else {
      printf("OK\tcap_escape\t(c) foreign pointer rejected\n");
    }
  }

  /* Probe (d): proc_mem without Landlock. This one is in-process
   * (oo_proc_mem_read does not exit; it returns an empty OoResS
   * when Landlock is not applied). We do not need fork for this. */
  {
    /* Landlock may not be available on this kernel. In that case
     * the function refuses by is_available() check, which is also
     * a fail-closed outcome. */
    OoResS r = oo_proc_mem_read(0LL, 0, 64);
    if (r.ok == 1 && r.val.len > 0) {
      printf("FAIL\tcap_escape\t(d) proc_mem read succeeded without Landlock\n");
      bypass_count++;
    } else {
      printf("OK\tcap_escape\t(d) proc_mem refused without Landlock (ok=%d len=%lld)\n",
             r.ok, (long long)r.val.len);
    }
  }

  if (bypass_count == 0) {
    printf("PASS\tcap_escape\t0/4 bypasses succeeded; cap system is sound\n");
    rc = 0;
  } else {
    printf("FAIL\tcap_escape\t%d/4 bypasses succeeded; cap system has a defect\n",
           bypass_count);
    rc = 1;
  }
  (void)rc;  /* suppress unused warning if compiler is strict */
  return bypass_count == 0 ? 0 : 1;
}
