/* sys_exec_wait.c — fork+execvp, inherit stdio, wait for exit code.
 * ProcessCap. No shell. Child runs oo_child_filter_env. */
#include "../../oodar.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void oo_child_filter_env(void);

static char *oo_exec_wait_dup(OoStr s) {
  long long k;
  char *ac;
  if (!s.data || s.len <= 0) return NULL;
  for (k = 0; k < s.len; k++) {
    if (s.data[k] == '\0') return NULL;
  }
  ac = (char *)malloc((size_t)s.len + 1);
  if (!ac) return NULL;
  memcpy(ac, s.data, (size_t)s.len);
  ac[s.len] = '\0';
  return ac;
}

OoResI oo_sys_exec_wait(long long cap, OoStr cmd, OoSList a) {
  OoResI r;
  char **av;
  int argc;
  int i;
  int st;
  pid_t pid;
  long long extra;
  oo_cap_require_process(cap, "sys_exec_wait");
  r.ok = 0;
  r.val = 1;
  r.err = oo_str_lit("sys_exec_wait failed");
  extra = a.len > 0 ? a.len : 0;
  argc = 1 + (int)extra;
  av = (char **)calloc((size_t)argc + 1, sizeof(char *));
  if (!av) return r;
  av[0] = oo_exec_wait_dup(cmd);
  if (!av[0]) {
    free(av);
    return r;
  }
  for (i = 0; i < extra; i++) {
    av[i + 1] = oo_exec_wait_dup(a.data[i]);
    if (!av[i + 1]) {
      int j;
      for (j = 0; j <= i; j++) free(av[j]);
      free(av);
      return r;
    }
  }
  av[argc] = NULL;
  pid = fork();
  if (pid < 0) {
    for (i = 0; i < argc; i++) free(av[i]);
    free(av);
    return r;
  }
  if (pid == 0) {
    oo_child_filter_env();
    execvp(av[0], av);
    _exit(127);
  }
  for (i = 0; i < argc; i++) free(av[i]);
  free(av);
  if (waitpid(pid, &st, 0) < 0) return r;
  if (WIFEXITED(st)) {
    r.val = WEXITSTATUS(st);
    if (r.val == 0) {
      r.ok = 1;
      r.err = oo_str_lit("");
    } else {
      r.err = oo_str_lit("sys_exec_wait nonzero");
    }
    return r;
  }
  r.val = 1;
  r.err = oo_str_lit("sys_exec_wait signaled");
  return r;
}
