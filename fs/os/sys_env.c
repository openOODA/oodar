/* sys_env.c — environment-variable surface.
 * ZT path A: process-policy getenv is fail-closed for non OODA_/OO_ keys.
 * Product env_get (oo_env_get) still requires EnvCap.
 * oo_child_filter_env scrubs the child's environ to OODA_/OODAC_/OO_ keys
 * only and forces PATH=/usr/bin:/bin. oo_policy_write_on / oo_is_policy_path
 * gate the policy-path check used by fs.c and fs_dir.c. */
#include "../../oodar.h"
#include "../../oodar_internal.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ZT path A: process-policy getenv — fail-closed for non OODA_/OO_ keys.
 * Product env_get still requires EnvCap via oo_env_get. */
const char *oo_process_policy_getenv(const char *key) {
  if (!key || !key[0]) return NULL;
  if (strncmp(key, "OODA_", 5) != 0 && strncmp(key, "OO_", 3) != 0 && strcmp(key, "OODACODEX") != 0) {
    return NULL;
  }
  return getenv(key);
}

/* Child of sys_exec / sys_spawn: keep OODA_/OO_ keys only, then PATH=/usr/bin:/bin. */
void oo_child_filter_env(void) {
  extern char **environ;
  char **src;
  char **newenv = NULL;
  size_t n = 0, env_cap = 0;
  if (environ) {
    for (src = environ; *src; src++) {
      const char *eq = strchr(*src, '=');
      size_t klen;
      if (!eq) continue;
      klen = (size_t)(eq - *src);
      if (klen == 0) continue;
      if (!((klen >= 5 && strncmp(*src, "OODA_", 5) == 0) ||
            (klen >= 6 && strncmp(*src, "OODAC_", 6) == 0) ||
            (klen == 9 && strncmp(*src, "OODACODEX", 9) == 0) ||
            (klen >= 3 && strncmp(*src, "OO_", 3) == 0)))
        continue;
      if (n + 1 >= env_cap) {
        env_cap = env_cap ? env_cap * 2 : 16;
        newenv = (char **)realloc(newenv, env_cap * sizeof(char *));
        if (!newenv) _exit(127);
      }
      newenv[n++] = *src;
    }
  }
#if defined(__GLIBC__) || defined(__APPLE__)
  clearenv();
#else
  if (environ) {
    environ[0] = NULL;
  }
#endif
  if (newenv) {
    newenv[n] = NULL;
    environ = newenv;
  }
  setenv("PATH", "/usr/bin:/bin", 1);
}

int oo_policy_write_on(void) {
  const char *v = oo_process_policy_getenv("OODA_POLICY_WRITE");
  return v && v[0] == '1' && v[1] == '\0';
}

int oo_is_policy_path(const char *p) {
  const char *b;
  size_t n;
  if (!p || !p[0]) return 0;
  if (strstr(p, "/.config/ooda/")) return 1;
  b = strrchr(p, '/');
  b = b ? b + 1 : p;
  if (strcmp(b, "SOUL.md") == 0 || strcmp(b, "soul.md") == 0) return 1;
  if (strcmp(b, ".bashrc") == 0 || strcmp(b, "ooda.lock") == 0) return 1;
  n = strlen(b);
  if (n >= 10 && strcmp(b + (n - 10), ".agent.pin") == 0) return 1;
  return 0;
}

/* Product env-get: EnvCap-gated read of an OODA_/OO_ env var. */
OoResS oo_env_get(long long cap, OoStr key) {
  oo_cap_require_env(cap, "env_get");
  OoResS r;
  const char *val = oo_process_policy_getenv(key.data ? key.data : "");
  if (val) {
    r.ok = 1;
    r.val = oo_str_lit(val);
  } else {
    r.ok = 0;
    r.val = oo_str_lit("env var not set");
  }
  return r;
}
