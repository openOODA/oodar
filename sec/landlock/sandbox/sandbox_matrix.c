#include "../../../oodar.h"
#include "../sandbox.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* sandbox_matrix.c — per-platform kernel-sandbox apply helpers.
 *
 * Each helper takes an oo_sandbox_config_t and returns the OoResS for
 * that platform's enforcement path. The orchestrator (sandbox.c)
 * dispatches to the correct helper based on oo_sandbox_probe_backend().
 *
 * These helpers are non-static (no static keyword) so the orchestrator
 * in the same TU can call them. The helpers themselves are file-local
 * in spirit — they are only called from oo_sandbox_apply_matrix. The
 * Linux branch (Landlock + cap-based seccomp + rlimits) lives in
 * sandbox_config.c because it bridges to oo_landlock_restrict. */

#if defined(__APPLE__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

OoResS sand_darwin_seatbelt_apply(const oo_sandbox_config_t *cfg) {
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
OoResS sand_openbsd_sandbox_apply(const oo_sandbox_config_t *cfg) {
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
OoResS sand_freebsd_capsicum_apply(const oo_sandbox_config_t *cfg) {
  (void)cfg;
  if (cap_enter() != 0) {
    return (OoResS){0, oo_str_lit("ERR\tcapsicum\tcap_enter failed")};
  }
  return (OoResS){1, oo_str_lit("OK_FREEBSD_CAPSICUM_ENFORCED")};
}
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
OoResS sand_win32_sandbox_apply(const oo_sandbox_config_t *cfg) {
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
