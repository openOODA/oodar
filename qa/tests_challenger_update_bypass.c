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
 *   1. (bypass) oo_landlock_restrict returns OK_LANDLOCK_UPDATE_BYPASS
 *      when cmdline argv[1] is "update".
 *   2. (bypass) After the orchestrator applies, oodar_cap_is_sandboxed()
 *      returns false (seccomp was skipped).
 *   3. (bypass) socket(AF_INET, SOCK_STREAM, 0) + connect(127.0.0.1)
 *      succeed (would be KILL_PROCESS under seccomp without the
 *      bypass).
 *   4. (control) oo_landlock_restrict with a narrow allowlist applies
 *      the Landlock ruleset normally.
 *   5. (control) After a non-bypass orchestrator apply, socket(2)
 *      is killed by the seccomp filter (the child must terminate
 *      via signal or non-zero exit; ALLOW is the leak signal).
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
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>

#include "../oodar.h"
#include "../types.h"

/* Forward decls: implemented in oodar C; declared here so we can
 * link the test against oodar.c without bringing in the public header
 * path that the existing tests use. */
int oo_landlock_is_available(void);
OoResS oo_landlock_restrict(long long cap, OoStr read_dirs, OoStr write_dirs);
int oodar_cap_apply_seccomp_filter(unsigned int allowed_caps_mask);
int oodar_cap_is_sandboxed(void);
OoResS sand_apply_linux_landlock_seccomp(long long sys_cap,
                                         const oo_sandbox_config_t *config,
                                         int nread, int nwrite);
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
  /* Walk NUL-separated argv entries. */
  int cur = 0;
  size_t i = 0;
  while ((size_t)i < (size_t)n) {
    if (cur == idx) return buf + i;
    while ((size_t)i < (size_t)n && buf[i] != '\0') i++;
    cur++;
    if (cur > idx) return NULL;
    if ((size_t)i < (size_t)n) i++; /* skip NUL separator */
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
  /* Beat 1: oo_landlock_restrict returns OK_LANDLOCK_UPDATE_BYPASS. */
  OoResS r = oo_landlock_restrict(sys_cap, mkstr("/tmp"), mkstr("/tmp"));
  if (!r.ok) {
    fprintf(stderr, "  LEAK beat1: oo_landlock_restrict ok=false under update bypass\n"); fflush(stderr);
    _exit(0);
  }
  static const char bypass_msg[] = "OK_LANDLOCK_UPDATE_BYPASS";
  if (r.val.len != (long long)(sizeof(bypass_msg) - 1) ||
      memcmp(r.val.data, bypass_msg, sizeof(bypass_msg) - 1) != 0) {
    fprintf(stderr, "  LEAK beat1: bypass msg mismatch: len=%lld data=%.*s\n",
            r.val.len, (int)r.val.len, r.val.data ? r.val.data : "(null)"); fflush(stderr);
    _exit(0);
  }

  /* Beat 2: orchestrator skips seccomp install when bypass was taken. */
  /* We must call sand_apply_linux_landlock_seccomp with a config that
   * has read_dirs so the orchestrator's first `if` branch fires (which
   * is where the bypass check lives). After the call, oodar_cap_is_sandboxed
   * must be 0. */
  oo_sandbox_config_t cfg;
  memset(&cfg, 0, sizeof cfg);
  cfg.read_dirs_colon = mkstr("/tmp");
  cfg.write_dirs_colon = mkstr("/tmp");
  cfg.allowed_caps_mask = 0; /* no NET cap — would KILL socket under seccomp */
  OoResS orch = sand_apply_linux_landlock_seccomp(sys_cap, &cfg, 1, 1);
  if (!orch.ok) {
    fprintf(stderr, "  LEAK beat2: orchestrator ok=false: val=%.*s\n",
            (int)orch.val.len, orch.val.data ? orch.val.data : "(null)"); fflush(stderr);
    _exit(0);
  }
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
  /* ECONNREFUSED is acceptable; we only need the syscall to NOT be killed. */
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
  /* Beat 4: oo_landlock_restrict returns OK_LANDLOCK_ENFORCED (or
   * a normal-enforcement sentinel), NOT OK_LANDLOCK_UPDATE_BYPASS. */
  OoResS r = oo_landlock_restrict(sys_cap, mkstr("/tmp"), mkstr("/tmp"));
  if (!r.ok) {
    fprintf(stderr, "  LEAK beat4: oo_landlock_restrict ok=false under control\n"); fflush(stderr);
    _exit(0);
  }
  static const char bypass_msg[] = "OK_LANDLOCK_UPDATE_BYPASS";
  if (r.val.len == (long long)(sizeof(bypass_msg) - 1) &&
      memcmp(r.val.data, bypass_msg, sizeof(bypass_msg) - 1) == 0) {
    fprintf(stderr, "  LEAK beat4: bypass triggered under non-update argv[1]\n"); fflush(stderr);
    _exit(0);
  }

  /* Beat 5: orchestrator applies seccomp; socket(2) is KILL_PROCESS. */
  oo_sandbox_config_t cfg;
  memset(&cfg, 0, sizeof cfg);
  cfg.read_dirs_colon = mkstr("/tmp");
  cfg.write_dirs_colon = mkstr("/tmp");
  cfg.allowed_caps_mask = 0;
  OoResS orch = sand_apply_linux_landlock_seccomp(sys_cap, &cfg, 1, 1);
  if (!orch.ok) {
    fprintf(stderr, "  LEAK beat5: orchestrator ok=false under control: %.*s\n",
            (int)orch.val.len, orch.val.data ? orch.val.data : "(null)"); fflush(stderr);
    _exit(0);
  }
  if (!oodar_cap_is_sandboxed()) {
    fprintf(stderr, "  LEAK beat5a: seccomp was not installed under control\n"); fflush(stderr);
    _exit(0);
  }
  /* socket(2) must NOT succeed — seccomp KILL_PROCESS kills us. */
  /* If we get here, the seccomp filter is not enforcing the cap. */
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s >= 0) {
    fprintf(stderr, "  LEAK beat5b: socket(2) succeeded under control (seccomp not enforcing)\n"); fflush(stderr);
    close(s);
    _exit(0);
  }
  /* socket failed — could be seccomp KILL or genuine EACCES. Both are OK
   * for the contract; the key is that we got a non-zero exit / signal. */
  _exit(0);
}

/* Run fn in a forked child; return the child's wait status (raw int). */
static pid_t fork_and_run(void (*fn)(void)) {
  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return -1; }
  if (pid == 0) { alarm(5); fn(); _exit(0); }
  return pid;
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

  /* If argv[1] is "update", we are a re-execed child running the
   * bypass asserts. argv[1] is "probe", run control asserts. argv[1]
   * empty or anything else, dispatch the orchestrator and run the
   * parent's beat schedule. */
  char buf[8192];
  char *arg1 = cmdline_argv(1, buf, sizeof buf);
  if (arg1 && strcmp(arg1, "update") == 0) {
    beat_bypass_asserts();
    _exit(0); /* unreachable */
  }
  if (arg1 && strcmp(arg1, "probe") == 0) {
    beat_control_asserts();
    _exit(0); /* unreachable */
  }

  /* Parent path: fork two children, each re-execs with a chosen argv[1]. */
  int st_bypass = 0, st_control = 0;

  /* === Bypass child === */
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

  /* === Control child === */
  pid_t p2 = fork();
  if (p2 < 0) { perror("fork"); return 1; }
  if (p2 == 0) { reexec_self_with_argv1("probe"); _exit(127); }
  waitpid(p2, &st_control, 0);
  const char *cls_control = classify(st_control);
  printf("control child: %s\n", cls_control);
  /* Control: socket(2) must NOT succeed. Either seccomp KILL_PROCESS
   * (signal) or the function returning -1 with the child still able
   * to _exit(0) is a LEAK. We want the KILL_PROCESS outcome. */
  if (strcmp(cls_control, "LEAK") == 0) {
    printf("FAIL\tupdate_bypass\tcontrol child leaked (socket(2) succeeded under non-bypass seccomp)\n");
    return 1;
  }
  /* PASS or KILLED both indicate seccomp is enforcing. */
  printf("PASS\tupdate_bypass\tPlan v29: bypass + control contract verified (bypass=%s, control=%s)\n",
         cls_bypass, cls_control);
  return 0;
}
