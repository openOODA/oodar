/* sys.c — process-exec + args + exit orchestrator.
 * The stdin/file_stamp/env surfaces live in sys_stdin.c, sys_stamp.c, sys_env.c.
 * The process-policy getenv filter (oo_process_policy_getenv) is re-exported
 * here as a forward decl because the ZT path-A contract ties it to the
 * child-exec flow (oo_sys_exec / oo_child_filter_env).
 * Cap tokens: oo_sys_exec / oo_sys_args need ProcessCap. */
#include "../../oodar.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

/* The env-typed helpers (oo_child_filter_env, oo_policy_write_on,
 * oo_is_policy_path, oo_env_get) live in sys_env.c. Forward decls: */
const char *oo_process_policy_getenv(const char *key);
void oo_child_filter_env(void);

/* R2/R3: fork + execvp with full argv (no system(3) shell). Captures the
 * child's stdout and stderr via one pipe so an Err payload carries printed
 * diagnostics (println on stdout, cap/landlock on stderr). Bounded to
 * OO_SYS_EXEC_MAX_OUT bytes (16MiB so emit-c concat of a product main
 * fits); a flood sees EPIPE. r.val holds the capture on Ok and Err. */
#define OO_SYS_EXEC_MAX_OUT (1u << 24)

OoResS oo_sys_exec(long long cap, int argc, OoStr *argv) {
  OoResS r;
  char **av;
  int i, st;
  long long k;
  pid_t pid;
  int pipefd[2];
  char *out_buf = NULL;
  size_t out_n = 0;
  oo_cap_require_process(cap, "sys_exec");
  r.ok = 0;
  r.val = oo_str_lit("sys_exec failed");
  if (argc < 1 || !argv || !argv[0].data) return r;
  if (pipe(pipefd) < 0) return r;
  av = (char **)calloc((size_t)argc + 1, sizeof(char *));
  if (!av) { close(pipefd[0]); close(pipefd[1]); return r; }
  for (i = 0; i < argc; i++) {
    /* Fail-closed like to_cpath: empty / len<=0 / NUL inside .len → no exec. */
    if (!argv[i].data || argv[i].len <= 0) {
      free(av);
      close(pipefd[0]); close(pipefd[1]);
      return r;
    }
    for (k = 0; k < argv[i].len; k++) {
      if (argv[i].data[k] == '\0') {
        free(av);
        close(pipefd[0]); close(pipefd[1]);
        return r;
      }
    }
    char *ac = (char *)malloc((size_t)argv[i].len + 1);
    if (!ac) { for (int j = 0; j < i; j++) free(av[j]); free(av); close(pipefd[0]); close(pipefd[1]); return r; }
    memcpy(ac, argv[i].data, (size_t)argv[i].len);
    ac[argv[i].len] = '\0';
    av[i] = ac;
  }
  av[argc] = NULL;
  out_buf = oo_str_alloc_payload(OO_SYS_EXEC_MAX_OUT);
  if (!out_buf) {
    for (i = 0; i < argc; i++) free(av[i]);
    free(av); close(pipefd[0]); close(pipefd[1]);
    return r;
  }
  pid = fork();
  if (pid < 0) {
    for (i = 0; i < argc; i++) free(av[i]);
    free(av);
    { OoStr tmp; tmp.data = out_buf; tmp.len = 0; oo_str_release(tmp); }
    close(pipefd[0]); close(pipefd[1]);
    return r;
  }
  if (pid == 0) {
    close(pipefd[0]);
    if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
    if (dup2(pipefd[1], STDERR_FILENO) < 0) _exit(126);
    close(pipefd[1]);
    oo_child_filter_env();
    execvp(av[0], av);
    _exit(127);
  }
  close(pipefd[1]);
  for (;;) {
    ssize_t got = read(pipefd[0], out_buf + out_n, OO_SYS_EXEC_MAX_OUT - out_n);
    if (got <= 0) break;
    out_n += (size_t)got;
    if (out_n >= OO_SYS_EXEC_MAX_OUT) break;
  }
  close(pipefd[0]);
  for (i = 0; i < argc; i++) free(av[i]);
  free(av);
  if (waitpid(pid, &st, 0) < 0) {
    OoStr tmp; tmp.data = out_buf; tmp.len = 0; oo_str_release(tmp);
    return r;
  }
  if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
    r.ok = 1;
  }
  r.val.data = out_buf;
  r.val.len = (long long)out_n;
  return r;
}

OoSList oo_sys_args(long long cap) {
  oo_cap_require_process(cap, "sys_args");
  OoSList l = oo_slist_new();
  FILE *f = fopen("/proc/self/cmdline", "rb");
  if (!f) return l;
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  if (n == 0) return l;
  size_t start = 0;
  size_t i;
  int first = 1;
  for (i = 0; i < n; i++) {
    if (buf[i] == '\0') {
      if (!first) {
        OoStr arg = oo_str_lit(buf + start);
        OoSList next = oo_slist_push(l, arg);
        oo_slist_release(l);
        l = next;
        oo_str_release(arg);
      }
      first = 0;
      start = i + 1;
    }
  }
  return l;
}

void oo_process_exit(long long c) {
  exit((int)c);
}
