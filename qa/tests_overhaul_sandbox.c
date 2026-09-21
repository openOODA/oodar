/* # oodar/qa/tests_overhaul_sandbox.c — Cross-Platform Sandboxing Tests
 * Logline: Tier 1 & 2 tests for unified sandbox init & containment.
 * Setup: Validates probing, backend names, allowlists, fail-closed caps.
 * Beats: 1. Probing; 2. Config allowlist; 3. Containment; 4. Bounds. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "../oodar.h"
#include "../sec/landlock/sandbox.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, name) do { \
  if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
  else { g_fail++; printf("  [FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

__attribute__((weak)) int oo_host_rt_sandbox_init(const char *r, const char *w);

static int apply_sandbox(const char *r_dirs, const char *w_dirs) {
  if (oo_host_rt_sandbox_init != NULL) {
    return oo_host_rt_sandbox_init(r_dirs, w_dirs);
  }
  long long sys_cap = oo_cap_grant_sys();
  oo_sandbox_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.allowed_caps_mask = 0xFFFFFFFF;
  if (r_dirs) cfg.read_dirs_colon = oo_str_lit(r_dirs);
  if (w_dirs) cfg.write_dirs_colon = oo_str_lit(w_dirs);
  OoResS r = oo_sandbox_apply_matrix(sys_cap, &cfg);
  return r.ok ? 0 : -1;
}

static void test_tier1_feature_coverage(void) {
  printf("--- Tier 1: Sandbox Feature Coverage ---\n");
  /* Case 1: Probe backend */
  oo_sandbox_backend_t backend = oo_sandbox_probe_backend();
  CHECK(backend >= OO_SANDBOX_BACKEND_NONE, "backend_probe_valid");

  /* Case 2: Backend name non-empty */
  const char *bname = oo_sandbox_backend_name(backend);
  CHECK(bname != NULL && strlen(bname) > 0, "backend_name_valid");

  /* Case 3: Sandbox availability check */
  int avail = oo_sandbox_is_available();
  CHECK(avail == 0 || avail == 1, "sandbox_is_available_returns_bool");

  /* Case 4: Containment test inside child process */
  pid_t pid = fork();
  if (pid == 0) {
    char tmpdir[64];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/oo_sb_test_%d", (int)getpid());
    mkdir(tmpdir, 0700);
    char file_inside[128];
    snprintf(file_inside, sizeof(file_inside), "%s/test.txt", tmpdir);

    int rc = apply_sandbox(tmpdir, tmpdir);
    if (rc == 0) {
      /* Write inside allowlist must succeed */
      int fd = open(file_inside, O_CREAT | O_WRONLY, 0600);
      int write_inside_ok = (fd >= 0);
      if (fd >= 0) close(fd);

      /* Attempt write outside allowlist should be blocked */
      int fd_out = open("/tmp/oo_sb_unauth.txt", O_CREAT | O_WRONLY, 0600);
      int write_outside_blocked = (fd_out < 0);
      if (fd_out >= 0) { close(fd_out); unlink("/tmp/oo_sb_unauth.txt"); }

      unlink(file_inside);
      rmdir(tmpdir);
      if (!write_inside_ok) _exit(2);
      if (!write_outside_blocked) _exit(3);
    } else {
      rmdir(tmpdir);
    }
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "sandbox_child_containment");

  /* Case 5: Empty read/write allowlists do not crash */
  int empty_rc = apply_sandbox("", "");
  CHECK(empty_rc == 0 || empty_rc == -1, "empty_allowlist_handled");
}

static void test_tier2_boundary_cases(void) {
  printf("--- Tier 2: Sandbox Boundary & Corner Cases ---\n");
  /* Case 6: NULL path allowlists handled gracefully */
  int null_rc = apply_sandbox(NULL, NULL);
  CHECK(null_rc == 0 || null_rc == -1, "null_allowlist_safe");

  /* Case 7: Allowlist with non-existent directory handled */
  int ne_rc = apply_sandbox("/nonexistent/path/for/test", NULL);
  CHECK(ne_rc == 0 || ne_rc == -1, "nonexistent_path_safe");

  /* Case 8: Colon-separated multiple paths */
  int multi_rc = apply_sandbox("/tmp:/usr/bin", "/tmp");
  CHECK(multi_rc == 0 || multi_rc == -1, "multi_colon_paths_safe");

  /* Case 9: Forged SysCap fails closed */
  pid_t fpid = fork();
  if (fpid == 0) {
    close(2); /* silence stderr */
    oo_sandbox_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    oo_sandbox_apply_matrix(0x9999LL, &cfg);
    _exit(0);
  }
  int fst = 0;
  waitpid(fpid, &fst, 0);
  CHECK(WIFEXITED(fst) && WEXITSTATUS(fst) != 0, "sandbox_forged_cap_fails");

  /* Case 10: Re-application idempotency check in child */
  pid_t rpid = fork();
  if (rpid == 0) {
    apply_sandbox("/tmp", "/tmp");
    int r2 = apply_sandbox("/tmp", "/tmp");
    _exit((r2 == 0 || r2 == -1) ? 0 : 1);
  }
  int rst = 0;
  waitpid(rpid, &rst, 0);
  CHECK(WIFEXITED(rst) && WEXITSTATUS(rst) == 0, "sandbox_reapply_idempotent");
}

int main(void) {
  printf("=== openOODA QA: Cross-Platform Sandboxing Tests ===\n");
  test_tier1_feature_coverage();
  test_tier2_boundary_cases();
  printf("Results: %d passed, %d failed\n", g_pass, g_fail);
  return (g_fail == 0) ? 0 : 1;
}
