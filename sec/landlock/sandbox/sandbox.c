#include "../../../oodar.h"
#include "../sandbox.h"
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/resource.h>
#elif defined(__APPLE__)
#include <sys/resource.h>
#elif defined(__OpenBSD__)
#include <sys/resource.h>
#elif defined(__FreeBSD__)
#include <sys/resource.h>
#elif defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#else
#include <sys/resource.h>
#endif

/* sandbox.c — the sandbox orchestrator.
 *
 * Owns the g_sand_* state (mutex, net/proc notes, locked/avail flags,
 * the active status struct, and the read/write dir caches) and the
 * public entry points that don't fit sandbox_matrix.c (probe,
 * is_available, status, the main apply_matrix dispatcher, the
 * restrict_caps and set_quotas shortcuts).
 *
 * Per-platform apply helpers for the non-Linux backends live in
 * sandbox_matrix.c. The Linux Landlock+seccomp+rlimits branch, the
 * legacy seccomp-only apply, the config validation/storage/status
 * helpers, and the seccomp BPF builder all live in sandbox_config.c
 * because they bridge to oo_landlock_restrict / oodar_cap_apply_seccomp_filter
 * / oo_rlimit_set_*. The v2.2.0 C-ABI backdoor family lives in
 * sandbox_c.c. */

/* Forward declarations for cross-file helpers defined in sandbox_config.c
 * (included after this file in the umbrella, so the compiler hasn't
 * seen their definitions yet when this file is processed). The
 * per-platform apply helpers (sand_darwin_seatbelt_apply etc.) are
 * defined in sandbox_matrix.c, which is included between this file
 * and sandbox_config.c, so they need no forward declaration here. */
static int sand_validate_paths(OoStr dirs, int *count);
static OoResS sand_apply_linux_landlock_seccomp(long long sys_cap, const oo_sandbox_config_t *config, int nread, int nwrite);
static void sand_store_dirs(const oo_sandbox_config_t *config);
static void sand_update_status_from_config(const oo_sandbox_config_t *config, oo_sandbox_backend_t backend, int nread, int nwrite);

/* g_sand_* state — non-static so sandbox_config.c (in the same TU
 * via the umbrella) can update the status struct and dir caches after
 * a successful matrix apply, and read the net/proc notes / locked
 * flag during the legacy oo_sandbox_apply path. The mutex is also
 * non-static for the same reason. */
pthread_mutex_t g_sand_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_sand_net = 0;
static int g_sand_proc = 0;
static int g_sand_locked = 0;
static int g_sand_avail = -1; /* -1 unknown, 0 no, 1 yes */
oo_sandbox_status_t g_sand_status = {
  0, OO_SANDBOX_BACKEND_NONE, 0, 0, 0, 0, 0
};
char g_sand_read_dirs[4096] = {0};
char g_sand_write_dirs[4096] = {0};

void oo_sandbox_note_net(void) {
  pthread_mutex_lock(&g_sand_mu);
  g_sand_net = 1;
  pthread_mutex_unlock(&g_sand_mu);
}

void oo_sandbox_note_proc(void) {
  pthread_mutex_lock(&g_sand_mu);
  g_sand_proc = 1;
  pthread_mutex_unlock(&g_sand_mu);
}

oo_sandbox_backend_t oo_sandbox_probe_backend(void) {
#if defined(__linux__)
#if defined(PR_SET_SECCOMP) || defined(__NR_landlock_create_ruleset)
  return OO_SANDBOX_BACKEND_LINUX_LANDLOCK_SECCOMP;
#else
  return OO_SANDBOX_BACKEND_VIRTUALIZED_FALLBACK;
#endif
#elif defined(__APPLE__)
  return OO_SANDBOX_BACKEND_DARWIN_SEATBELT;
#elif defined(__OpenBSD__)
  return OO_SANDBOX_BACKEND_OPENBSD_PLEDGE_UNVEIL;
#elif defined(__FreeBSD__)
  return OO_SANDBOX_BACKEND_FREEBSD_CAPSICUM;
#elif defined(_WIN32) || defined(__CYGWIN__)
  return OO_SANDBOX_BACKEND_WINDOWS_APPCONTAINER_JOB;
#else
  return OO_SANDBOX_BACKEND_VIRTUALIZED_FALLBACK;
#endif
}

const char *oo_sandbox_backend_name(oo_sandbox_backend_t backend) {
  switch (backend) {
    case OO_SANDBOX_BACKEND_NONE:
      return "none";
    case OO_SANDBOX_BACKEND_LINUX_LANDLOCK_SECCOMP:
      return "linux_landlock_seccomp";
    case OO_SANDBOX_BACKEND_DARWIN_SEATBELT:
      return "darwin_seatbelt";
    case OO_SANDBOX_BACKEND_OPENBSD_PLEDGE_UNVEIL:
      return "openbsd_pledge_unveil";
    case OO_SANDBOX_BACKEND_FREEBSD_CAPSICUM:
      return "freebsd_capsicum";
    case OO_SANDBOX_BACKEND_WINDOWS_APPCONTAINER_JOB:
      return "windows_appcontainer_job";
    case OO_SANDBOX_BACKEND_VIRTUALIZED_FALLBACK:
      return "virtualized_fallback";
    default:
      return "unknown";
  }
}

int oo_sandbox_is_available(void) {
  oo_sandbox_backend_t b = oo_sandbox_probe_backend();
  return (b != OO_SANDBOX_BACKEND_NONE && b != OO_SANDBOX_BACKEND_VIRTUALIZED_FALLBACK) ? 1 : 0;
}

int oo_sandbox_available(void) {
  return oo_sandbox_is_available();
}

oo_sandbox_status_t oo_sandbox_status(void) {
  oo_sandbox_status_t st;
  pthread_mutex_lock(&g_sand_mu);
  st = g_sand_status;
  pthread_mutex_unlock(&g_sand_mu);
  return st;
}

OoResS oo_sandbox_apply_matrix(long long sys_cap, const oo_sandbox_config_t *config) {
  oo_cap_require_sys(sys_cap, "sandbox_apply_matrix");
  if (!config) {
    return (OoResS){0, oo_str_lit("ERR\tsandbox\tnull configuration")};
  }

  int nread = 0, nwrite = 0;
  int pr = sand_validate_paths(config->read_dirs_colon, &nread);
  int pw = sand_validate_paths(config->write_dirs_colon, &nwrite);
  if (pr == -3 || pw == -3) return (OoResS){0, oo_str_lit("ERR\tsandbox\tpath not absolute")};
  if (pr == -2 || pw == -2) return (OoResS){0, oo_str_lit("ERR\tsandbox\tpath too long")};
  if (pr == -1 || pw == -1) return (OoResS){0, oo_str_lit("ERR\tsandbox\tembedded NUL in path")};
  if (nread + nwrite > 64) return (OoResS){0, oo_str_lit("ERR\tsandbox\ttoo many paths")};

  pthread_mutex_lock(&g_sand_mu);

  oo_sandbox_backend_t backend = oo_sandbox_probe_backend();
  OoResS res = {1, oo_str_lit("OK")};

  if (backend == OO_SANDBOX_BACKEND_LINUX_LANDLOCK_SECCOMP) {
    res = sand_apply_linux_landlock_seccomp(sys_cap, config, nread, nwrite);
    if (!res.ok) {
      pthread_mutex_unlock(&g_sand_mu);
      return res;
    }
  }
#if defined(__APPLE__)
  else if (backend == OO_SANDBOX_BACKEND_DARWIN_SEATBELT) {
    res = sand_darwin_seatbelt_apply(config);
    if (!res.ok) {
      pthread_mutex_unlock(&g_sand_mu);
      return res;
    }
    if (config->max_mem_mb > 0) oo_rlimit_set_mem_mb(sys_cap, config->max_mem_mb);
    if (config->max_cpu_sec > 0) oo_rlimit_set_cpu_sec(sys_cap, config->max_cpu_sec);
    if (config->max_nofile > 0) oo_rlimit_set_nofile(sys_cap, config->max_nofile);
  }
#elif defined(__OpenBSD__)
  else if (backend == OO_SANDBOX_BACKEND_OPENBSD_PLEDGE_UNVEIL) {
    res = sand_openbsd_sandbox_apply(config);
    if (!res.ok) {
      pthread_mutex_unlock(&g_sand_mu);
      return res;
    }
    if (config->max_mem_mb > 0) oo_rlimit_set_mem_mb(sys_cap, config->max_mem_mb);
    if (config->max_cpu_sec > 0) oo_rlimit_set_cpu_sec(sys_cap, config->max_cpu_sec);
    if (config->max_nofile > 0) oo_rlimit_set_nofile(sys_cap, config->max_nofile);
  }
#elif defined(__FreeBSD__)
  else if (backend == OO_SANDBOX_BACKEND_FREEBSD_CAPSICUM) {
    res = sand_freebsd_capsicum_apply(config);
    if (!res.ok) {
      pthread_mutex_unlock(&g_sand_mu);
      return res;
    }
    if (config->max_mem_mb > 0) oo_rlimit_set_mem_mb(sys_cap, config->max_mem_mb);
    if (config->max_cpu_sec > 0) oo_rlimit_set_cpu_sec(sys_cap, config->max_cpu_sec);
    if (config->max_nofile > 0) oo_rlimit_set_nofile(sys_cap, config->max_nofile);
  }
#elif defined(_WIN32) || defined(__CYGWIN__)
  else if (backend == OO_SANDBOX_BACKEND_WINDOWS_APPCONTAINER_JOB) {
    res = sand_win32_sandbox_apply(config);
    if (!res.ok) {
      pthread_mutex_unlock(&g_sand_mu);
      return res;
    }
  }
#endif
  else {
    /* No real kernel sandbox (Landlock, seccomp, Seatbelt, Capsicum, Pledge,
     * AppContainer) is available on this platform. Fail closed unconditionally:
     * the legacy "Virtualized Fallback" backend was a no-op that falsely
     * claimed enforcement without actually confining anything, which is a
     * silent security failure. The OO_SANDBOX_BACKEND_VIRTUALIZED_FALLBACK
     * enum value is retained (deprecated) only to keep existing
     * oo_sandbox_probe_backend / oo_sandbox_backend_name references
     * compiling; the runtime path must never reach it. */
    pthread_mutex_unlock(&g_sand_mu);
    return (OoResS){0, oo_str_lit("ERR\tsandbox\tkernel primitive unavailable, fail closed")};
  }

  sand_store_dirs(config);
  sand_update_status_from_config(config, backend, nread, nwrite);
  g_sand_locked = 1;

  pthread_mutex_unlock(&g_sand_mu);
  return res;
}

OoResS oo_sandbox_restrict_caps(long long sys_cap, uint32_t allowed_caps_mask) {
  oo_cap_require_sys(sys_cap, "sandbox_restrict_caps");
  oo_sandbox_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.allowed_caps_mask = allowed_caps_mask;
  return oo_sandbox_apply_matrix(sys_cap, &cfg);
}

OoResS oo_sandbox_set_quotas(long long sys_cap, long long mem_mb, long long cpu_sec, long long max_fds) {
  oo_cap_require_sys(sys_cap, "sandbox_set_quotas");
  if (mem_mb < 0 || cpu_sec < 0 || max_fds < 0) {
    return (OoResS){0, oo_str_lit("ERR\tsandbox\tnegative quota parameter")};
  }
  if (mem_mb > 0) {
    OoResS r = oo_rlimit_set_mem_mb(sys_cap, mem_mb);
    if (!r.ok) return r;
  }
  if (cpu_sec > 0) {
    OoResS r = oo_rlimit_set_cpu_sec(sys_cap, cpu_sec);
    if (!r.ok) return r;
  }
  if (max_fds > 0) {
    OoResS r = oo_rlimit_set_nofile(sys_cap, max_fds);
    if (!r.ok) return r;
  }
  pthread_mutex_lock(&g_sand_mu);
  g_sand_status.quotas_enforced = 1;
  pthread_mutex_unlock(&g_sand_mu);
  return (OoResS){1, oo_str_lit("OK")};
}
