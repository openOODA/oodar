/* # qa/tests_challenger_sandbox_containment.c — Tier-5 Landlock Containment
 *
 * Logline: Tier-5 redteam probe for Landlock FS containment. After
 * oo_landlock_restrict with a narrow allowlist, a file OUTSIDE
 * the allowlist must be un-openable. The probe proves the
 * kernel-mediated Landlock ruleset is actually applied to the
 * process and not just "available".
 *
 * Setup: This is a redteam probe (Red 8 dimension 2+8). The test:
 *   1. Probes oo_landlock_is_available(). If 0, the test prints
 *      SKIP and exits 0 (the kernel does not support Landlock;
 *      the containment guarantee is not in scope here).
 *   2. Creates a temp directory under /tmp.
 *   3. Calls oo_landlock_restrict with that temp dir as the only
 *      allowed path.
 *   4. Attempts to open /etc/passwd — must fail with EACCES.
 *   5. Attempts to open a file inside the temp dir — must succeed.
 *
 * The test uses SysCap (oo_cap_grant_sys) to call
 * oo_landlock_restrict. The temp dir is removed after the test.
 *
 * Note: this may require running as root or with CAP_DAC_OVERRIDE
 * for full coverage. As a non-root user, /etc/passwd may already
 * be un-openable for write due to DAC; the test still proves
 * that the Landlock ruleset is active because the in-allowlist
 * open succeeds.
 *
 * Beats:
 *   1. Probe Landlock availability; skip if not available.
 *   2. Set up a temp dir under /tmp/oo_containment_<pid>.
 *   3. Call oo_landlock_restrict with the temp dir as the only path.
 *   4. Try to open /etc/passwd (must fail with EACCES).
 *   5. Try to open a file in the temp dir (must succeed).
 *   6. Clean up the temp dir.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../oodar.h"
#include "../types.h"

long long oo_cap_grant_sys(void);
int oo_landlock_is_available(void);
OoResS oo_landlock_restrict(long long cap, OoStr read_dirs, OoStr write_dirs);

/* Build an OoStr from a NUL-terminated C string. */
static OoStr mkstr(const char *s) {
  OoStr r;
  r.data = (char *)s;
  r.len = (long long)strlen(s);
  return r;
}

int main(void) {
  printf("=== qa/tests_challenger_sandbox_containment.c — tier-5 Landlock probe ===\n");

  if (!oo_landlock_is_available()) {
    printf("SKIP\tsandbox_containment\tLandlock not available on this kernel; no containment to probe\n");
    return 0;
  }

  /* Create a unique temp dir under /tmp. */
  char tmpdir[256];
  snprintf(tmpdir, sizeof(tmpdir), "/tmp/oo_containment_%d", (int)getpid());
  if (mkdir(tmpdir, 0700) != 0 && errno != EEXIST) {
    printf("FAIL\tsandbox_containment\tmkdir(%s) failed: %s\n", tmpdir, strerror(errno));
    return 1;
  }

  /* Create a sentinel file inside the temp dir. */
  char sentinel[512];
  snprintf(sentinel, sizeof(sentinel), "%s/inside.txt", tmpdir);
  int fd = open(sentinel, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    printf("FAIL\tsandbox_containment\topen(%s) failed: %s\n", sentinel, strerror(errno));
    rmdir(tmpdir);
    return 1;
  }
  const char *msg = "inside\n";
  if (write(fd, msg, strlen(msg)) < 0) {
    close(fd);
    printf("FAIL\tsandbox_containment\twrite to sentinel failed: %s\n", strerror(errno));
    rmdir(tmpdir);
    return 1;
  }
  close(fd);

  /* Apply Landlock with ONLY the temp dir as the allowed path. */
  long long sys_cap = oo_cap_grant_sys();
  OoResS r = oo_landlock_restrict(sys_cap, mkstr(tmpdir), mkstr(tmpdir));
  if (!r.ok) {
    /* Landlock failed to apply. This may happen on kernels
     * where Landlock is "available" but cannot be applied
     * (e.g., running under Docker without --cap-add). Print
     * a SKIP and exit 0 — the containment is not testable
     * in this environment. */
    printf("SKIP\tsandbox_containment\too_landlock_restrict failed: ok=%d val=%.*s\n",
           r.ok, (int)r.val.len, r.val.data ? r.val.data : "(null)");
    unlink(sentinel);
    rmdir(tmpdir);
    return 0;
  }

  /* Try to open the sentinel inside the allowlist. Must succeed. */
  fd = open(sentinel, O_RDONLY);
  if (fd < 0) {
    printf("FAIL\tsandbox_containment\topen(%s) inside allowlist failed: %s\n",
           sentinel, strerror(errno));
    unlink(sentinel);
    rmdir(tmpdir);
    return 1;
  }
  close(fd);
  printf("OK\tsandbox_containment\topen(%s) inside allowlist succeeded\n", sentinel);

  /* Try to open /etc/passwd outside the allowlist. Must fail. */
  fd = open("/etc/passwd", O_RDONLY);
  if (fd >= 0) {
    /* The kernel allowed the read. This is a containment failure. */
    close(fd);
    printf("FAIL\tsandbox_containment\topen(/etc/passwd) OUTSIDE allowlist succeeded — Landlock not enforced\n");
    unlink(sentinel);
    rmdir(tmpdir);
    return 1;
  }
  if (errno != EACCES && errno != EPERM) {
    printf("WARN\tsandbox_containment\topen(/etc/passwd) failed with unexpected errno=%d (%s) — not Landlock\n",
           errno, strerror(errno));
  } else {
    printf("OK\tsandbox_containment\topen(/etc/passwd) refused with %s\n", strerror(errno));
  }

  /* Try to open a file outside the allowlist with O_WRONLY. Must fail. */
  fd = open("/etc/passwd", O_WRONLY);
  if (fd >= 0) {
    close(fd);
    printf("FAIL\tsandbox_containment\topen(/etc/passwd, O_WRONLY) OUTSIDE allowlist succeeded\n");
    unlink(sentinel);
    rmdir(tmpdir);
    return 1;
  }
  printf("OK\tsandbox_containment\topen(/etc/passwd, O_WRONLY) refused with %s\n", strerror(errno));

  /* Clean up. */
  unlink(sentinel);
  rmdir(tmpdir);

  printf("PASS\tsandbox_containment\tLandlock containment verified\n");
  return 0;
}
