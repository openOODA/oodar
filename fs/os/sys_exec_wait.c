/* sys_exec_wait.c — posix_spawnp, inherit stdio, wait for exit code.
 * ProcessCap. No shell. Child uses localized filtered environment. */
#include "../../oodar.h"
#include <errno.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static char *oo_cstr_dup(const char *s) {
  size_t len;
  char *d;
  if (!s) return NULL;
  len = strlen(s);
  d = (char *)malloc(len + 1);
  if (!d) return NULL;
  memcpy(d, s, len + 1);
  return d;
}

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

static int oo_env_matches_filter(const char *entry) {
  const char *eq;
  size_t klen;
  if (!entry) return 0;
  eq = strchr(entry, '=');
  if (!eq) return 0;
  klen = (size_t)(eq - entry);
  if (klen == 0) return 0;
  if ((klen >= 5 && strncmp(entry, "OODA_", 5) == 0) ||
      (klen >= 6 && strncmp(entry, "OODAC_", 6) == 0) ||
      (klen == 9 && strncmp(entry, "OODACODEX", 9) == 0) ||
      (klen == 3 && strncmp(entry, "PWD", 3) == 0) ||
      (klen >= 3 && strncmp(entry, "OO_", 3) == 0)) {
    return 1;
  }
  /* PATH is passed through unconditionally (the standard exec convention).
   * Filtered from the policy scrub above; the build path below checks
   * whether a PATH survived the filter and falls back to a hardcoded
   * minimal list only when the parent had none. This avoids injecting
   * /usr/local/bin (a privileged shadow point) into environments that
   * the caller already trusted enough to inherit. */
  if (klen == 4 && strncmp(entry, "PATH", 4) == 0) {
    return 1;
  }
  return 0;
}

static void oo_free_child_env(char **child_env) {
  size_t i;
  if (!child_env) return;
  for (i = 0; child_env[i]; i++) {
    free(child_env[i]);
  }
  free(child_env);
}

static char **oo_build_child_env(void) {
  extern char **environ;
  char **envp;
  size_t count = 0;
  size_t idx = 0;
  int path_inherited = 0;
  if (environ) {
    for (char **e = environ; *e; e++) {
      if (oo_env_matches_filter(*e)) {
        count++;
        if (strncmp(*e, "PATH=", 5) == 0) path_inherited = 1;
      }
    }
  }
  /* Always reserve a slot for PATH (either inherited or fallback). */
  envp = (char **)calloc(count + 2, sizeof(char *));
  if (!envp) return NULL;
  if (environ) {
    for (char **e = environ; *e; e++) {
      if (oo_env_matches_filter(*e)) {
        envp[idx] = oo_cstr_dup(*e);
        if (!envp[idx]) {
          oo_free_child_env(envp);
          return NULL;
        }
        idx++;
      }
    }
  }
  if (!path_inherited) {
    envp[idx] = oo_cstr_dup("PATH=/usr/local/bin:/usr/bin:/bin");
    if (!envp[idx]) {
      oo_free_child_env(envp);
      return NULL;
    }
    idx++;
  }
  envp[idx] = NULL;
  return envp;
}

static void oo_free_av(char **av, int argc) {
  int i;
  if (!av) return;
  for (i = 0; i < argc; i++) {
    if (av[i]) free(av[i]);
  }
  free(av);
}

OoResI oo_sys_exec_wait(long long cap, OoStr cmd, OoSList a) {
  OoResI r;
  char **av;
  char **child_env;
  int argc;
  int i;
  int st;
  int rc;
  int wrc;
  pid_t pid;
  long long extra;
  posix_spawnattr_t attr;

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
      oo_free_av(av, i + 1);
      return r;
    }
  }
  av[argc] = NULL;

  child_env = oo_build_child_env();
  if (!child_env) {
    oo_free_av(av, argc);
    return r;
  }

  posix_spawnattr_init(&attr);
  posix_spawnattr_setflags(&attr, POSIX_SPAWN_USEVFORK);

  rc = posix_spawnp(&pid, av[0], NULL, &attr, av, child_env);
  posix_spawnattr_destroy(&attr);

  oo_free_av(av, argc);
  oo_free_child_env(child_env);

  if (rc != 0) {
    return r;
  }

  do {
    wrc = waitpid(pid, &st, 0);
  } while (wrc < 0 && errno == EINTR);

  if (wrc < 0) return r;

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
