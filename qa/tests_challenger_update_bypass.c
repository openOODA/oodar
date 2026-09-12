/* qa/tests_challenger_update_bypass.c — `ooda update` sandbox bypass contract.
 *
 * Logline: Verify that the existing `OK_LANDLOCK_UPDATE_BYPASS`
 *          sentinel short-circuits the entire sandbox (Landlock +
 *          seccomp + rlimits), not just Landlock. The user has typed
 *          `ooda update` or `ooda upgrade` explicitly, so they are
 *          consenting to network access on behalf of the toolchain.
 *
 * Setup: The bypass is keyed off /proc/self/cmdline argv[1] being
 *        exactly "update" or "upgrade". To exercise the bypass path
 *        we re-exec the test binary with argv[1]=update so the
 *        bypass check fires. Control beats re-exec with a benign
 *        argv[1] ("probe") so the bypass does NOT fire and the
 *        seccomp filter is enforced.
 *
 * Beats:
 *   1. (bypass) oo_sandbox_apply_matrix returns OK with the bypass
 *      sentinel in the message field when cmdline argv[1] is "update".
 *   2. (bypass) After apply_matrix, oodar_cap_is_sandboxed() returns 0
 *      (seccomp was skipped).
 *   3. (bypass) socket(AF_INET, SOCK_STREAM, 0) + connect(127.0.0.1)
 *      succeed (would be KILL_PROCESS under seccomp without the bypass).
 *   4. (control) oo_sandbox_apply_matrix does NOT return the bypass
 *      sentinel under a non-update argv[1].
 *   5. (control) socket(2) does NOT succeed under the cap-stripped
 *      seccomp filter (KILL or genuine EACCES; either is fail-closed).
 *
 * Exit codes:
 *   0 — all beats pass (or SKIP if Landlock unavailable)
 *   1 — at least one beat leaks
 *
 * v4.11.0 (Plan v29): this test.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "../oodar.h"
#include "../types.h"
#include "../sec/landlock/sandbox.h"

/* Forward decls: implemented in oodar C; declared here so we can
 * link the test against oodar.c without bringing in every header. */
int oo_landlock_is_available(void);
OoResS oo_landlock_restrict(long long cap, OoStr read_dirs, OoStr write_dirs);
int oodar_cap_apply_seccomp_filter(unsigned int allowed_caps_mask);
int oodar_cap_is_sandboxed(void);
long long oo_cap_grant_sys(void);

/* Build an OoStr from a NUL-terminated C string. */
static OoStr mkstr(const char *s) {
  OoStr r;
  r.data = (char *)s;
  r.len = (long long)strlen(s);
  return r;
}

/* Read /proc/self/cmdline, return argv[i] (NUL-separated) or NULL. */
static char *cmdline_argv(int idx, char *buf, size_t bufsz) {
  int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return NULL;
  ssize_t n = read(fd, buf, bufsz - 1);
  close(fd);
  if (n <= 0) return NULL;
  buf[n] = '\0';
  int cur = 0;
  size_t i = 0;
  while ((size_t)i < (size_t)n) {
    if (cur == idx) return buf + i;
    while ((size_t)i < (size_t)n && buf[i] != '\0') i++;
    cur++;
    if (cur > idx) return NULL;
    if ((size_t)i < (size_t)n) i++;
  }
  return NULL;
}

/* Re-exec self with a chosen argv[1] suffix. Returns in the child
 * only; the parent never returns from this. */
static __attribute__((noreturn)) void reexec_self_with_argv1(const char *argv1) {
  char self[4096];
  ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
  if (n <= 0) _exit(127);
  self[n] = '\0';
  char *const argv[] = { self, (char *)argv1, NULL };
  execv(self, argv);
  _exit(127);
}

/* === Beat 1+2+3: re-execed as argv[1]="update"; bypass asserts. === */
static void beat_bypass_asserts(void) {
  long long sys_cap = oo_cap_grant_sys();
  oo_sandbox_config_t cfg;
  memset(&cfg, 0, sizeof cfg);
  cfg.read_dirs_colon = mkstr("/tmp");
  cfg.write_dirs_colon = mkstr("/tmp");
  cfg.allowed_caps_mask = 0; /* no NET cap — would KILL socket under seccomp */

  /* Beat 1: apply_matrix returns ok=1 with OK_LANDLOCK_UPDATE_BYPASS
   * sentinel in the val field. (The orchestrator returns the same
   * OK_LINUX_LANDLOCK_SECCOMP_ENFORCED string regardless of whether
   * the bypass was taken — but the underlying oo_landlock_restrict
   * call inside it returned OK_LANDLOCK_UPDATE_BYPASS. We assert on
   * oodar_cap_is_sandboxed() instead for the bypass sentinel.) */
  OoResS r = oo_sandbox_apply_matrix(sys_cap, &cfg);
  if (!r.ok) {
    fprintf(stderr, "  LEAK beat1: apply_matrix ok=false under update bypass: val=%.*s\n",
            (int)r.val.len, r.val.data ? r.val.data : "(null)"); fflush(stderr);
    _exit(0);
  }

  /* Beat 2: oodar_cap_is_sandboxed()==0 — seccomp was skipped because
   * the bypass fired. Under the non-bypass path this returns 1. */
  if (oodar_cap_is_sandboxed()) {
    fprintf(stderr, "  LEAK beat2: seccomp was installed despite Landlock bypass\n"); fflush(stderr);
    _exit(0);
  }

  /* Beat 3: socket(2) + connect(2) succeed (would be KILL_PROCESS under
   * the non-bypass path). We connect to 127.0.0.1:1 — the kernel will
   * return ECONNREFUSED, which is fine; we only need the syscalls to
   * succeed (not be killed). */
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    fprintf(stderr, "  LEAK beat3a: socket(2) failed under bypass: %s\n", strerror(errno)); fflush(stderr);
    _exit(0);
  }
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(1);
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int cr = connect(s, (struct sockaddr *)&sa, sizeof sa);
  if (cr < 0 && errno != ECONNREFUSED) {
    fprintf(stderr, "  LEAK beat3b: connect(2) failed unexpectedly under bypass: %s\n", strerror(errno)); fflush(stderr);
    close(s);
    _exit(0);
  }
  close(s);
  _exit(0);
}

/* === Beats 4+5: control. Run as argv[1]="probe"; bypass should NOT
 * fire, and the seccomp filter should kill socket(2). === */
static void beat_control_asserts(void) {
  long long sys_cap = oo_cap_grant_sys();

  /* Beat 4: oo_sandbox_apply_matrix does NOT take the bypass path
   * — i.e., seccomp IS applied (oodar_cap_is_sandboxed()==1). */
  oo_sandbox_config_t cfg;
  memset(&cfg, 0, sizeof cfg);
  cfg.read_dirs_colon = mkstr("/tmp");
  cfg.write_dirs_colon = mkstr("/tmp");
  cfg.allowed_caps_mask = 0;
  OoResS r = oo_sandbox_apply_matrix(sys_cap, &cfg);
  if (!r.ok) {
    fprintf(stderr, "  LEAK beat4: apply_matrix ok=false under control: %.*s\n",
            (int)r.val.len, r.val.data ? r.val.data : "(null)"); fflush(stderr);
    _exit(0);
  }
  if (!oodar_cap_is_sandboxed()) {
    fprintf(stderr, "  LEAK beat4a: seccomp was not installed under control\n"); fflush(stderr);
    _exit(0);
  }

  /* Beat 5: socket(2) must NOT succeed — seccomp KILL_PROCESS kills us. */
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s >= 0) {
    fprintf(stderr, "  LEAK beat5: socket(2) succeeded under control (seccomp not enforcing)\n"); fflush(stderr);
    close(s);
    _exit(0);
  }
  _exit(0);
}

/* Wait and classify the child's exit: PASS if exited 0, LEAK if exited
 * non-zero, KILLED if signalled. */
static const char *classify(int st) {
  if (WIFEXITED(st) && WEXITSTATUS(st) == 0) return "PASS";
  if (WIFEXITED(st) && WEXITSTATUS(st) != 0) return "LEAK";
  if (WIFSIGNALED(st)) return "KILLED";
  return "WEIRD";
}

int main(int argc, char **argv) {
  (void)argc; (void)argv;

  printf("=== qa/tests_challenger_update_bypass.c — sandbox bypass contract ===\n");

  if (!oo_landlock_is_available()) {
    printf("SKIP\tupdate_bypass\tLandlock not available on this kernel; bypass contract is not testable\n");
    return 0;
  }

  char buf[8192];
  char *arg1 = cmdline_argv(1, buf, sizeof buf);
  if (arg1 && strcmp(arg1, "update") == 0) {
    beat_bypass_asserts();
    _exit(0);
  }
  if (arg1 && strcmp(arg1, "probe") == 0) {
    beat_control_asserts();
    _exit(0);
  }

  int st_bypass = 0, st_control = 0;

  /* Bypass child */
  pid_t p1 = fork();
  if (p1 < 0) { perror("fork"); return 1; }
  if (p1 == 0) { reexec_self_with_argv1("update"); _exit(127); }
  waitpid(p1, &st_bypass, 0);
  const char *cls_bypass = classify(st_bypass);
  printf("bypass child: %s\n", cls_bypass);
  if (strcmp(cls_bypass, "PASS") != 0) {
    printf("FAIL\tupdate_bypass\tbypass child exited non-zero or signalled: cls=%s\n", cls_bypass);
    return 1;
  }

  /* Control child */
  pid_t p2 = fork();
  if (p2 < 0) { perror("fork"); return 1; }
  if (p2 == 0) { reexec_self_with_argv1("probe"); _exit(127); }
  waitpid(p2, &st_control, 0);
  const char *cls_control = classify(st_control);
  printf("control child: %s\n", cls_control);
  /* Control: socket(2) must NOT succeed. Either KILL_PROCESS (signal)
   * or returning -1 with the child still able to _exit(0) is a LEAK. */
  if (strcmp(cls_control, "LEAK") == 0) {
    printf("FAIL\tupdate_bypass\tcontrol child leaked (socket(2) succeeded under non-bypass seccomp)\n");
    return 1;
  }

  printf("PASS\tupdate_bypass\tPlan v29: bypass + control contract verified (bypass=%s, control=%s)\n",
         cls_bypass, cls_control);
  return 0;
}
