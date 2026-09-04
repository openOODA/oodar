#include "chs_rt.h"
#include "chs_rt_rlimit.h"
#include <errno.h>
#include <string.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <jobapi2.h>

/* One job per process; AssignProcessToJobObject may only be called once,
 * so we keep a process-wide handle and re-use it for subsequent limit
 * updates. Kernel keeps its own reference, so we can safely close our
 * handle after the first assignment. */
static HANDLE g_rlimit_job = NULL;
static LONG g_rlimit_assigned = 0;

static HANDLE rlimit_get_job(int *assigned) {
  if (assigned) *assigned = (g_rlimit_assigned != 0);
  return g_rlimit_job;
}

OoResS oo_rlimit_set_mem_mb(long long cap, long long megabytes) {
  oo_cap_require_sys(cap, "rlimit_set_mem");
  if (megabytes <= 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tinvalid memory quota size")};
  }
  HANDLE hJob = g_rlimit_job;
  int already_assigned = (g_rlimit_assigned != 0);
  if (!hJob) {
    hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to create job object")};
    g_rlimit_job = hJob;
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
  memset(&jeli, 0, sizeof(jeli));
  jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
  jeli.ProcessMemoryLimit = (SIZE_T)megabytes * 1024 * 1024;
  jeli.JobMemoryLimit = (SIZE_T)megabytes * 1024 * 1024;
  if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to set job memory limit")};
  }
  if (!already_assigned) {
    if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
      return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to assign job")};
    }
    g_rlimit_assigned = 1;
  }
  return (OoResS){1, oo_str_lit("OK")};
}

/* Windows has no per-process fd limit primitive. Fail closed: the
 * requested quota is not silently accepted. */
OoResS oo_rlimit_set_nofile(long long cap, long long max_fds) {
  oo_cap_require_sys(cap, "rlimit_set_nofile");
  (void)max_fds;
  return (OoResS){0, oo_str_lit("ERR\trlimit\tnofile not supported on this platform")};
}

OoResS oo_rlimit_set_cpu_sec(long long cap, long long seconds) {
  oo_cap_require_sys(cap, "rlimit_set_cpu");
  if (seconds <= 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tinvalid cpu seconds")};
  }
  HANDLE hJob = g_rlimit_job;
  int already_assigned = (g_rlimit_assigned != 0);
  if (!hJob) {
    hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to create job object")};
    g_rlimit_job = hJob;
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
  memset(&jeli, 0, sizeof(jeli));
  jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_TIME;
  jeli.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = (LONGLONG)seconds * 10000000LL;
  if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to set job cpu limit")};
  }
  if (!already_assigned) {
    if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
      return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to assign job")};
    }
    g_rlimit_assigned = 1;
  }
  return (OoResS){1, oo_str_lit("OK")};
}

#else
#include <sys/resource.h>
#include <sys/time.h>

/* rlim_max is preserved as the existing hard limit (lowering it below the
 * current soft value makes setrlimit fail with EPERM for non-root). Only
 * the soft limit is tightened to the requested value. */

OoResS oo_rlimit_set_mem_mb(long long cap, long long megabytes) {
  oo_cap_require_sys(cap, "rlimit_set_mem");
  if (megabytes <= 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tinvalid memory quota size")};
  }
  struct rlimit rl;
  rlim_t bytes = (rlim_t)megabytes * 1024ULL * 1024ULL;
  if (getrlimit(RLIMIT_AS, &rl) != 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to get RLIMIT_AS")};
  }
  rl.rlim_cur = bytes;
  if (bytes < rl.rlim_max) rl.rlim_max = bytes;
  if (setrlimit(RLIMIT_AS, &rl) != 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to set RLIMIT_AS")};
  }
  return (OoResS){1, oo_str_lit("OK")};
}

OoResS oo_rlimit_set_nofile(long long cap, long long max_fds) {
  oo_cap_require_sys(cap, "rlimit_set_nofile");
  if (max_fds <= 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tinvalid fd count")};
  }
  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to get RLIMIT_NOFILE")};
  }
  rl.rlim_cur = (rlim_t)max_fds;
  if ((rlim_t)max_fds < rl.rlim_max) rl.rlim_max = (rlim_t)max_fds;
  if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to set RLIMIT_NOFILE")};
  }
  return (OoResS){1, oo_str_lit("OK")};
}

OoResS oo_rlimit_set_cpu_sec(long long cap, long long seconds) {
  oo_cap_require_sys(cap, "rlimit_set_cpu");
  if (seconds <= 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tinvalid cpu seconds")};
  }
  struct rlimit rl;
  if (getrlimit(RLIMIT_CPU, &rl) != 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to get RLIMIT_CPU")};
  }
  rl.rlim_cur = (rlim_t)seconds;
  if ((rlim_t)seconds < rl.rlim_max) rl.rlim_max = (rlim_t)seconds;
  if (setrlimit(RLIMIT_CPU, &rl) != 0) {
    return (OoResS){0, oo_str_lit("ERR\trlimit\tfailed to set RLIMIT_CPU")};
  }
  return (OoResS){1, oo_str_lit("OK")};
}
#endif
