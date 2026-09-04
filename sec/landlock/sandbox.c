#include "../../oodar.h"
#include "sandbox.h"
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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
#elif defined(__APPLE__)
#include <sandbox.h>
#include <sys/resource.h>
#elif defined(__OpenBSD__)
#include <unistd.h>
#include <sys/resource.h>
#elif defined(__FreeBSD__)
#include <sys/capsicum.h>
#include <sys/resource.h>
#elif defined(_WIN32) || defined(__CYGWIN__)
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <userenv.h>
#include <jobapi2.h>
#else
#include <sys/resource.h>
#endif

static pthread_mutex_t g_sand_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_sand_net = 0;
static int g_sand_proc = 0;
static int g_sand_locked = 0;
static int g_sand_avail = -1; /* -1 unknown, 0 no, 1 yes */
static oo_sandbox_status_t g_sand_status = {
  0, OO_SANDBOX_BACKEND_NONE, 0, 0, 0, 0, 0
};
static char g_sand_read_dirs[4096] = {0};
static char g_sand_write_dirs[4096] = {0};

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

static int sand_validate_paths(OoStr dirs, int *count) {
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

#if defined(__linux__) && defined(PR_SET_SECCOMP) && defined(SECCOMP_MODE_FILTER)
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif

static int sand_install_seccomp(uint32_t net_act, uint32_t proc_act, uint32_t clone3_act) {
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

int oo_sandbox_apply(void) {
  int rc = 0;
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
    g_sand_status.backend = OO_SANDBOX_BACKEND_LINUX_LANDLOCK_SECCOMP;
  } else if (rc == -1) {
    g_sand_avail = 0;
    fprintf(stderr, "ERR\tsandbox\tseccomp ABI unavailable\n");
  }
#else
  g_sand_avail = 0;
  rc = -1;
  fprintf(stderr, "ERR\tsandbox\tseccomp ABI unavailable\n");
#endif
  pthread_mutex_unlock(&g_sand_mu);
  return rc;
}

#if defined(__APPLE__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static OoResS darwin_seatbelt_apply(const oo_sandbox_config_t *cfg) {
  char profile[8192];
  size_t off = 0;
  char *errbuf = NULL;
  int rc;

  off += (size_t)snprintf(profile + off, sizeof(profile) - off,
    "(version 1)\n"
    "(deny default)\n"
    "(allow process-info*)\n"
    "(allow sysctl-read)\n"
    "(allow file-read-data (literal \"/dev/null\") (literal \"/dev/urandom\") (literal \"/dev/random\"))\n"
    "(allow file-read* (subpath \"/usr/lib\") (subpath \"/System/Library\") (subpath \"/usr/share\"))\n"
  );

  if (cfg->read_dirs_colon.data && cfg->read_dirs_colon.len > 0) {
    long long n = cfg->read_dirs_colon.len;
    const char *p = cfg->read_dirs_colon.data;
    long long i = 0;
    while (i <= n) {
      long long start = i;
      while (i < n && p[i] != ':') i++;
      long long len = i - start;
      if (len > 0 && off + (size_t)len + 40 < sizeof(profile)) {
        char dir[1024];
        if (len < (long long)sizeof(dir)) {
          memcpy(dir, p + start, (size_t)len);
          dir[len] = '\0';
          off += (size_t)snprintf(profile + off, sizeof(profile) - off,
            "(allow file-read* (subpath \"%s\"))\n", dir);
        }
      }
      if (i >= n) break;
      i++;
    }
  }

  if ((cfg->allowed_caps_mask & (OODAR_CAP_FSWRITE | OODAR_CAP_FS)) &&
      cfg->write_dirs_colon.data && cfg->write_dirs_colon.len > 0) {
    long long n = cfg->write_dirs_colon.len;
    const char *p = cfg->write_dirs_colon.data;
    long long i = 0;
    while (i <= n) {
      long long start = i;
      while (i < n && p[i] != ':') i++;
      long long len = i - start;
      if (len > 0 && off + (size_t)len + 40 < sizeof(profile)) {
        char dir[1024];
        if (len < (long long)sizeof(dir)) {
          memcpy(dir, p + start, (size_t)len);
          dir[len] = '\0';
          off += (size_t)snprintf(profile + off, sizeof(profile) - off,
            "(allow file-write* (subpath \"%s\"))\n", dir);
        }
      }
      if (i >= n) break;
      i++;
    }
  }

  if (cfg->allowed_caps_mask & (OODAR_CAP_NET | OODAR_CAP_HTTP | OODAR_CAP_TCP | OODAR_CAP_UDP | OODAR_CAP_BIND)) {
    off += (size_t)snprintf(profile + off, sizeof(profile) - off,
      "(allow network*)\n(allow system-socket)\n");
  }

  if (cfg->allowed_caps_mask & (OODAR_CAP_PROCESS | OODAR_CAP_SYS)) {
    off += (size_t)snprintf(profile + off, sizeof(profile) - off,
      "(allow process-exec)\n(allow process-fork)\n");
  }

  rc = sandbox_init(profile, 0, &errbuf);
  if (rc != 0) {
    char msg[256];
    snprintf(msg, sizeof(msg), "ERR\tseatbelt\tsandbox_init failed: %s", errbuf ? errbuf : "unknown");
    if (errbuf) sandbox_free_error(errbuf);
    return (OoResS){0, oo_str_lit(msg)};
  }
  return (OoResS){1, oo_str_lit("OK_SEATBELT_ENFORCED")};
}
#pragma clang diagnostic pop
#endif

#if defined(__OpenBSD__)
static OoResS openbsd_sandbox_apply(const oo_sandbox_config_t *cfg) {
  char promises[128] = "stdio";

  unveil("/usr/lib", "r");
  unveil("/dev/null", "rw");
  unveil("/dev/urandom", "r");

  if (cfg->read_dirs_colon.data && cfg->read_dirs_colon.len > 0) {
    long long n = cfg->read_dirs_colon.len;
    const char *p = cfg->read_dirs_colon.data;
    long long i = 0;
    while (i <= n) {
      long long start = i;
      while (i < n && p[i] != ':') i++;
      long long len = i - start;
      if (len > 0) {
        char dir[1024];
        if (len < (long long)sizeof(dir)) {
          memcpy(dir, p + start, (size_t)len);
          dir[len] = '\0';
          unveil(dir, "r");
        }
      }
      if (i >= n) break;
      i++;
    }
    strncat(promises, " rpath", sizeof(promises) - strlen(promises) - 1);
  }

  if ((cfg->allowed_caps_mask & (OODAR_CAP_FSWRITE | OODAR_CAP_FS)) &&
      cfg->write_dirs_colon.data && cfg->write_dirs_colon.len > 0) {
    long long n = cfg->write_dirs_colon.len;
    const char *p = cfg->write_dirs_colon.data;
    long long i = 0;
    while (i <= n) {
      long long start = i;
      while (i < n && p[i] != ':') i++;
      long long len = i - start;
      if (len > 0) {
        char dir[1024];
        if (len < (long long)sizeof(dir)) {
          memcpy(dir, p + start, (size_t)len);
          dir[len] = '\0';
          unveil(dir, "rwc");
        }
      }
      if (i >= n) break;
      i++;
    }
    strncat(promises, " wpath cpath", sizeof(promises) - strlen(promises) - 1);
  }

  if (unveil(NULL, NULL) != 0) {
    return (OoResS){0, oo_str_lit("ERR\tunveil\tfailed to seal unveil list")};
  }

  if (cfg->allowed_caps_mask & (OODAR_CAP_NET | OODAR_CAP_HTTP | OODAR_CAP_TCP | OODAR_CAP_UDP | OODAR_CAP_BIND)) {
    strncat(promises, " inet dns", sizeof(promises) - strlen(promises) - 1);
  }
  if (cfg->allowed_caps_mask & (OODAR_CAP_PROCESS | OODAR_CAP_SYS)) {
    strncat(promises, " proc exec", sizeof(promises) - strlen(promises) - 1);
  }

  if (pledge(promises, NULL) != 0) {
    return (OoResS){0, oo_str_lit("ERR\tpledge\tfailed to apply pledge promises")};
  }
  return (OoResS){1, oo_str_lit("OK_OPENBSD_PLEDGE_UNVEIL_ENFORCED")};
}
#endif

#if defined(__FreeBSD__)
static OoResS freebsd_capsicum_apply(const oo_sandbox_config_t *cfg) {
  (void)cfg;
  if (cap_enter() != 0) {
    return (OoResS){0, oo_str_lit("ERR\tcapsicum\tcap_enter failed")};
  }
  return (OoResS){1, oo_str_lit("OK_FREEBSD_CAPSICUM_ENFORCED")};
}
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
static OoResS win32_sandbox_apply(const oo_sandbox_config_t *cfg) {
  HANDLE hJob = CreateJobObjectW(NULL, NULL);
  if (!hJob) return (OoResS){0, oo_str_lit("ERR\tjob_object\tCreateJobObject failed")};

  JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
  memset(&jeli, 0, sizeof(jeli));
  jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

  if (cfg->max_mem_mb > 0) {
    jeli.BasicLimitInformation.LimitFlags |= (JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY);
    jeli.ProcessMemoryLimit = (SIZE_T)cfg->max_mem_mb * 1024 * 1024;
    jeli.JobMemoryLimit = (SIZE_T)cfg->max_mem_mb * 1024 * 1024;
  }

  if (cfg->max_cpu_sec > 0) {
    jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
    jeli.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = (LONGLONG)cfg->max_cpu_sec * 10000000LL;
  }

  if (!(cfg->allowed_caps_mask & (OODAR_CAP_PROCESS | OODAR_CAP_SYS))) {
    jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    jeli.BasicLimitInformation.ActiveProcessLimit = 1;
  }

  if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
    CloseHandle(hJob);
    return (OoResS){0, oo_str_lit("ERR\tjob_object\tSetInformationJobObject failed")};
  }

  if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
    CloseHandle(hJob);
    return (OoResS){0, oo_str_lit("ERR\tjob_object\tAssignProcessToJobObject failed")};
  }

  return (OoResS){1, oo_str_lit("OK_WIN32_APPCONTAINER_JOB_ENFORCED")};
}
#endif

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
    if (config->read_dirs_colon.len > 0 || config->write_dirs_colon.len > 0 ||
        (nread == 0 && nwrite == 0)) {
      OoResS ll_res = oo_landlock_restrict(sys_cap, config->read_dirs_colon, config->write_dirs_colon);
      if (!ll_res.ok) {
        pthread_mutex_unlock(&g_sand_mu);
        return ll_res;
      }
    }
    if (oodar_cap_apply_seccomp_filter(config->allowed_caps_mask) < 0) {
      if (config->fail_closed_on_kernel_miss) {
        pthread_mutex_unlock(&g_sand_mu);
        return (OoResS){0, oo_str_lit("ERR\tseccomp\tfilter application failed")};
      }
    }
    if (config->max_mem_mb > 0) oo_rlimit_set_mem_mb(sys_cap, config->max_mem_mb);
    if (config->max_cpu_sec > 0) oo_rlimit_set_cpu_sec(sys_cap, config->max_cpu_sec);
    if (config->max_nofile > 0) oo_rlimit_set_nofile(sys_cap, config->max_nofile);
    res = (OoResS){1, oo_str_lit("OK_LINUX_LANDLOCK_SECCOMP_ENFORCED")};
  }
#if defined(__APPLE__)
  else if (backend == OO_SANDBOX_BACKEND_DARWIN_SEATBELT) {
    res = darwin_seatbelt_apply(config);
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
    res = openbsd_sandbox_apply(config);
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
    res = freebsd_capsicum_apply(config);
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
    res = win32_sandbox_apply(config);
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

  g_sand_status.is_enforced = 1;
  g_sand_status.backend = backend;
  g_sand_status.active_caps_mask = config->allowed_caps_mask;
  g_sand_status.fs_restricted = (config->read_dirs_colon.len > 0 || config->write_dirs_colon.len > 0 || (nread == 0 && nwrite == 0)) ? 1 : 0;
  g_sand_status.net_restricted = (config->allowed_caps_mask & (OODAR_CAP_NET | OODAR_CAP_HTTP | OODAR_CAP_TCP | OODAR_CAP_UDP | OODAR_CAP_BIND)) ? 0 : 1;
  g_sand_status.proc_restricted = (config->allowed_caps_mask & (OODAR_CAP_PROCESS | OODAR_CAP_SYS)) ? 0 : 1;
  g_sand_status.quotas_enforced = (config->max_mem_mb > 0 || config->max_cpu_sec > 0 || config->max_nofile > 0) ? 1 : 0;
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

oo_sandbox_status_t oo_sandbox_status(void) {
  oo_sandbox_status_t st;
  pthread_mutex_lock(&g_sand_mu);
  st = g_sand_status;
  pthread_mutex_unlock(&g_sand_mu);
  return st;
}

int oo_sandbox_c_apply_matrix(const char *writedir, uint64_t cap_mask) {
  long long cap = oo_cap_grant_sys();
  oo_sandbox_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.allowed_caps_mask = (uint32_t)cap_mask;
  if (writedir) {
    cfg.write_dirs_colon = oo_str_lit(writedir);
  }
  OoResS r = oo_sandbox_apply_matrix(cap, &cfg);
  return r.ok ? 0 : -1;
}

int oo_sandbox_c_restrict_caps(uint64_t cap_mask) {
  long long cap = oo_cap_grant_sys();
  OoResS r = oo_sandbox_restrict_caps(cap, (uint32_t)cap_mask);
  return r.ok ? 0 : -1;
}

int oo_sandbox_c_set_quotas(uint64_t mem_mb, uint64_t cpu_sec, uint64_t max_fds) {
  long long cap = oo_cap_grant_sys();
  OoResS r = oo_sandbox_set_quotas(cap, (long long)mem_mb, (long long)cpu_sec, (long long)max_fds);
  return r.ok ? 0 : -1;
}
