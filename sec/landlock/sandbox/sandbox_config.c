#include "../../../oodar.h"
#include "../sandbox.h"
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/resource.h>
#else
#include <sys/resource.h>
#endif

/* sandbox_config.c — OoSandConfig helpers + the seccomp apply path
 * + the Linux Landlock-apply logic that bridges oo_sandbox_apply_matrix
 * (in the orchestrator) to oo_landlock_restrict (in sec/landlock/landlock/
 * landlock_restrict.c).
 *
 * The cross-file helpers here are non-static so sandbox.c (the
 * orchestrator, in the same TU via the umbrella) can call them.
 * Per-backend apply helpers for the non-Linux platforms live in
 * sandbox_matrix.c. The C-ABI backdoor family lives in sandbox_c.c. */

/* Walk colon-separated dirs, validate that each entry is absolute
 * (or Windows drive / UNC on Win32) and count the entries. Returns
 * 0 on success or a negative code (-1 embedded NUL, -2 too long,
 * -3 not absolute). */
int sand_validate_paths(OoStr dirs, int *count) {
  long long n = dirs.data ? dirs.len : 0;
  const char *p = dirs.data;
  long long i = 0;
  if (n < 0) n = 0;
  while (i <= n) {
    long long start = i;
    while (i < n && p[i] != ':') {
      if (p[i] == '\0') return -1;
      i++;
    }
    long long len = i - start;
    if (len > 0) {
      if (len >= 4096) return -2;
      if (p[start] != '/'
#if defined(_WIN32) || defined(__CYGWIN__)
          && !(len >= 2 && isalpha((unsigned char)p[start]) && p[start+1] == ':')
          && !(len >= 2 && p[start] == '\\' && p[start+1] == '\\')
#endif
      ) {
        return -3;
      }
      if (count) (*count)++;
    }
    if (i >= n) break;
    i++;
  }
  return 0;
}

/* The Linux branch of the sandbox matrix: apply Landlock path
 * confinement, then the cap-based seccomp filter, then any rlimits.
 * Returns the result for the orchestrator to surface. */
OoResS sand_apply_linux_landlock_seccomp(long long sys_cap, const oo_sandbox_config_t *config, int nread, int nwrite) {
  (void)nwrite;
  if (config->read_dirs_colon.len > 0 || config->write_dirs_colon.len > 0 ||
      (nread == 0 && nwrite == 0)) {
    OoResS ll_res = oo_landlock_restrict(sys_cap, config->read_dirs_colon, config->write_dirs_colon);
    if (!ll_res.ok) {
      return ll_res;
    }
  }
  if (oodar_cap_apply_seccomp_filter(config->allowed_caps_mask) < 0) {
    return (OoResS){0, oo_str_lit("ERR\tseccomp\tfilter application failed")};
  }
  if (!oodar_cap_is_sandboxed()) {
    return (OoResS){0, oo_str_lit("ERR\tseccomp\tfilter not enforced")};
  }
  if (config->max_mem_mb > 0) oo_rlimit_set_mem_mb(sys_cap, config->max_mem_mb);
  if (config->max_cpu_sec > 0) oo_rlimit_set_cpu_sec(sys_cap, config->max_cpu_sec);
  if (config->max_nofile > 0) oo_rlimit_set_nofile(sys_cap, config->max_nofile);
  return (OoResS){1, oo_str_lit("OK_LINUX_LANDLOCK_SECCOMP_ENFORCED")};
}

/* Cache the active read/write dir allowlists so oo_sandbox_status()
 * consumers (and any later introspection) can see the live path
 * lists without re-deriving them from the config struct. */
void sand_store_dirs(const oo_sandbox_config_t *config) {
  if (config->read_dirs_colon.data && config->read_dirs_colon.len > 0) {
    size_t sz = (size_t)config->read_dirs_colon.len;
    if (sz >= sizeof(g_sand_read_dirs)) sz = sizeof(g_sand_read_dirs) - 1;
    memcpy(g_sand_read_dirs, config->read_dirs_colon.data, sz);
    g_sand_read_dirs[sz] = '\0';
  }
  if (config->write_dirs_colon.data && config->write_dirs_colon.len > 0) {
    size_t sz = (size_t)config->write_dirs_colon.len;
    if (sz >= sizeof(g_sand_write_dirs)) sz = sizeof(g_sand_write_dirs) - 1;
    memcpy(g_sand_write_dirs, config->write_dirs_colon.data, sz);
    g_sand_write_dirs[sz] = '\0';
  }
}

/* Derive the per-axis (fs/net/proc/quotas) status booleans from the
 * config that was just applied, and stamp them onto the global
 * status struct. The orchestrator calls this after a successful
 * per-platform apply, before flipping g_sand_locked to 1. */
void sand_update_status_from_config(const oo_sandbox_config_t *config, oo_sandbox_backend_t backend, int nread, int nwrite) {
  g_sand_status.is_enforced = 1;
  g_sand_status.backend = backend;
  g_sand_status.active_caps_mask = config->allowed_caps_mask;
  g_sand_status.fs_restricted = (config->read_dirs_colon.len > 0 || config->write_dirs_colon.len > 0 || (nread == 0 && nwrite == 0)) ? 1 : 0;
  /* v2.1.0: removed OODAR_CAP_HTTP (dead cap). Net restrict now means
   * NET | TCP | UDP | BIND — i.e., the four live net-class tokens. */
  g_sand_status.net_restricted = (config->allowed_caps_mask & (OODAR_CAP_NET | OODAR_CAP_TCP | OODAR_CAP_UDP | OODAR_CAP_BIND)) ? 0 : 1;
  g_sand_status.proc_restricted = (config->allowed_caps_mask & (OODAR_CAP_PROCESS | OODAR_CAP_SYS)) ? 0 : 1;
  g_sand_status.quotas_enforced = (config->max_mem_mb > 0 || config->max_cpu_sec > 0 || config->max_nofile > 0) ? 1 : 0;
}

#if defined(__linux__) && defined(PR_SET_SECCOMP) && defined(SECCOMP_MODE_FILTER)
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif

/* Build and install a seccomp BPF filter that gates network, fork,
 * and exec syscalls based on the per-axis actions passed in. This
 * is the legacy apply path (oo_sandbox_apply) that pre-dates the
 * cap-based oodar_cap_apply_seccomp_filter used by the matrix path. */
int sand_install_seccomp(uint32_t net_act, uint32_t proc_act, uint32_t clone3_act) {
  struct sock_filter f[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
#ifdef __NR_socket
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, net_act),
#endif
#ifdef __NR_connect
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, net_act),
#endif
#ifdef __NR_bind
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, net_act),
#endif
#ifdef __NR_fork
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, proc_act),
#endif
#ifdef __NR_vfork
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, proc_act),
#endif
#ifdef __NR_execve
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, proc_act),
#endif
#ifdef __NR_execveat
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, proc_act),
#endif
#ifdef __NR_clone3
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, clone3_act),
#endif
#ifdef __NR_clone
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET | BPF_K, proc_act),
#endif
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog;
  prog.len = (unsigned short)(sizeof f / sizeof f[0]);
  prog.filter = f;
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    if (errno == ENOSYS || errno == EINVAL) return -1;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
    if (errno == ENOSYS || errno == EPERM || errno == EINVAL) return -1;
    fprintf(stderr, "ERR\tsandbox\tseccomp apply failed errno=%d\n", errno);
    return -2;
  }
  return 0;
}
#endif

/* oo_sandbox_apply() — the legacy seccomp-only apply path.
 * Reads the g_sand_net / g_sand_proc notes (set via oo_sandbox_note_net
 * / oo_sandbox_note_proc) and installs a BPF filter that enforces
 * them. This pre-dates the cap-based oo_sandbox_apply_matrix; callers
 * that need Landlock + cap-based seccomp + rlimits should use
 * oo_sandbox_apply_matrix instead. */
int oo_sandbox_apply(long long sys_cap) {
  int rc = 0;
  oo_cap_require_sys(sys_cap, "sandbox_apply");
  pthread_mutex_lock(&g_sand_mu);
  if (g_sand_locked) {
    pthread_mutex_unlock(&g_sand_mu);
    return 0;
  }
#if defined(__linux__) && defined(PR_SET_SECCOMP) && defined(SECCOMP_MODE_FILTER)
  {
    uint32_t net_act = g_sand_net ? SECCOMP_RET_ALLOW : (SECCOMP_RET_ERRNO | EPERM);
    uint32_t proc_act = g_sand_proc ? SECCOMP_RET_ALLOW : (SECCOMP_RET_ERRNO | EPERM);
    uint32_t clone3_act = g_sand_proc ? SECCOMP_RET_ALLOW : (SECCOMP_RET_ERRNO | ENOSYS);
    rc = sand_install_seccomp(net_act, proc_act, clone3_act);
  }
  if (rc == 0) {
    g_sand_locked = 1;
    g_sand_avail = 1;
    g_sand_status.is_enforced = 1;
    g_sand_status.backend = OO_SANDBOX_BACKEND_SECCOMP;
  } else {
    g_sand_avail = 0;
    fprintf(stderr, "ERR\tsandbox\tseccomp filter application failed\n");
    pthread_mutex_unlock(&g_sand_mu);
    return -1;
  }
#else
  g_sand_avail = 0;
  rc = -1;
  fprintf(stderr, "ERR\tsandbox\tseccomp ABI unavailable\n");
  pthread_mutex_unlock(&g_sand_mu);
  return -1;
#endif
  pthread_mutex_unlock(&g_sand_mu);
  return rc;
}
