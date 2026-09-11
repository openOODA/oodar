#ifndef OODAR_SANDBOX_SYSCALLS_H
#define OODAR_SANDBOX_SYSCALLS_H

#include "../../types.h"

OoResI oo_landlock_create_ruleset_raw(long long cap, long long flags, long long handled_access_fs);
OoResI oo_landlock_add_rule_path_raw(long long cap, long long ruleset_fd, long long parent_fd, long long allowed_access);
OoResI oo_landlock_restrict_self_raw(long long cap, long long ruleset_fd, long long flags);
OoResI oo_landlock_abi_version_raw(long long cap);
OoResI oo_seccomp_apply_raw(long long cap, OoStr filter_blob);

#endif
