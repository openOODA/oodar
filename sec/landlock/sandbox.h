#ifndef OODAR_SANDBOX_H
#define OODAR_SANDBOX_H

#include "../../types.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Supported Kernel Sandbox Backends */
typedef enum {
    OO_SANDBOX_BACKEND_NONE = 0,
    OO_SANDBOX_BACKEND_LINUX_LANDLOCK_SECCOMP = 1,
    OO_SANDBOX_BACKEND_LANDLOCK = 1,
    OO_SANDBOX_BACKEND_DARWIN_SEATBELT = 2,
    OO_SANDBOX_BACKEND_SEATBELT = 2,
    OO_SANDBOX_BACKEND_OPENBSD_PLEDGE_UNVEIL = 3,
    OO_SANDBOX_BACKEND_PLEDGE = 3,
    OO_SANDBOX_BACKEND_FREEBSD_CAPSICUM = 4,
    OO_SANDBOX_BACKEND_CAPSICUM = 4,
    OO_SANDBOX_BACKEND_WINDOWS_APPCONTAINER_JOB = 5,
    OO_SANDBOX_BACKEND_APPCONTAINER = 5,
    /* DEPRECATED: virtualized fallback was a no-op that falsely claimed
     * enforcement. The runtime enforcement path in oo_sandbox_apply_matrix
     * no longer accepts this value and fails closed when no real kernel
     * backend is available. Retained only as a probe/availability sentinel. */
    OO_SANDBOX_BACKEND_VIRTUALIZED_FALLBACK = 6,
    OO_SANDBOX_BACKEND_VIRTUAL = 6,
    OO_SANDBOX_BACKEND_SECCOMP = 7
} oo_sandbox_backend_t;

/* Sandbox Configuration Structure */
typedef struct {
    uint32_t allowed_caps_mask;       /* Bitmask of OODAR_CAP_* tokens */
    OoStr read_dirs_colon;            /* Colon-separated read allowlist paths */
    OoStr write_dirs_colon;           /* Colon-separated write allowlist paths */
    long long max_mem_mb;             /* Maximum memory quota in MB (0 = unconstrained) */
    long long max_cpu_sec;            /* Maximum CPU execution time in seconds (0 = unconstrained) */
    long long max_nofile;             /* Maximum open file descriptors (0 = default) */
    int fail_closed_on_kernel_miss;   /* If 1, fail closed if OS kernel primitives are missing */
} oo_sandbox_config_t;

/* Runtime Sandbox Status Inspection Structure */
typedef struct {
    int is_enforced;                  /* 1 if sandbox is currently locked and active */
    oo_sandbox_backend_t backend;     /* Active backend identifier */
    uint32_t active_caps_mask;        /* Mask of currently permitted capabilities */
    int fs_restricted;                /* 1 if filesystem confinement is active */
    int net_restricted;               /* 1 if network confinement is active */
    int proc_restricted;              /* 1 if process creation is restricted */
    int quotas_enforced;              /* 1 if CPU/memory quotas are active */
} oo_sandbox_status_t;

/* Core Public API */
oo_sandbox_backend_t oo_sandbox_probe_backend(void);
const char *oo_sandbox_backend_name(oo_sandbox_backend_t backend);
int oo_sandbox_is_available(void);
int oo_sandbox_available(void);
void oo_sandbox_note_net(void);
void oo_sandbox_note_proc(void);
int oo_sandbox_apply(long long sys_cap);

OoResS oo_sandbox_apply_matrix(long long sys_cap, const oo_sandbox_config_t *config);
OoResS oo_sandbox_restrict_caps(long long sys_cap, uint32_t allowed_caps_mask);
OoResS oo_sandbox_set_quotas(long long sys_cap, long long mem_mb, long long cpu_sec, long long max_fds);
oo_sandbox_status_t oo_sandbox_status(void);

/* C Interface Helpers (v2.2.0: require sys_cap as first arg; the function
 * validates it with oo_cap_require_sys() and fails closed on mismatch) */
int oo_sandbox_c_apply_matrix(long long sys_cap, const char *writedir, uint64_t cap_mask);
int oo_sandbox_c_restrict_caps(long long sys_cap, uint64_t cap_mask);
int oo_sandbox_c_set_quotas(long long sys_cap, uint64_t mem_mb, uint64_t cpu_sec, uint64_t max_fds);

#ifdef __cplusplus
}
#endif

#endif /* OODAR_SANDBOX_H */
