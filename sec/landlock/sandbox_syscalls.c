/* sandbox_syscalls.c — Raw Linux Landlock LSM & Seccomp-BPF under SysCap.
 *
 * Implements:
 *   oo_landlock_create_ruleset_raw: syscall(SYS_landlock_create_ruleset)
 *   oo_landlock_add_rule_path_raw: syscall(SYS_landlock_add_rule)
 *   oo_landlock_restrict_self_raw: syscall(SYS_landlock_restrict_self)
 *   oo_landlock_abi_version_raw: syscall query LANDLOCK_CREATE_RULESET_VERSION
 *   oo_seccomp_apply_raw: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)
 *
 * Governed by RULES.oot <= 256 lines and zero ambient authority.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../../oodar.h"
#include "../../oodar_internal.h"
#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
#endif
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION 1U
#endif
#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

OoResI oo_landlock_create_ruleset_raw(long long cap, long long flags, long long handled_access_fs) {
  OoResI r;
  oo_cap_require_sys(cap, "landlock_create_ruleset");
  r.ok = 0; r.val = -1;
  struct landlock_ruleset_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.handled_access_fs = (uint64_t)handled_access_fs;
  int fd = (int)syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), (uint32_t)flags);
  if (fd < 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "landlock_create_ruleset: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = (long long)fd;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_landlock_add_rule_path_raw(long long cap, long long ruleset_fd, long long parent_fd, long long allowed_access) {
  OoResI r;
  oo_cap_require_sys(cap, "landlock_add_rule");
  r.ok = 0; r.val = -1;
  struct landlock_path_beneath_attr path_attr;
  memset(&path_attr, 0, sizeof(path_attr));
  path_attr.parent_fd = (int)parent_fd;
  path_attr.allowed_access = (uint64_t)allowed_access;
  int rc = (int)syscall(__NR_landlock_add_rule, (int)ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "landlock_add_rule: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_landlock_restrict_self_raw(long long cap, long long ruleset_fd, long long flags) {
  OoResI r;
  oo_cap_require_sys(cap, "landlock_restrict_self");
  r.ok = 0; r.val = -1;
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  int rc = (int)syscall(__NR_landlock_restrict_self, (int)ruleset_fd, (uint32_t)flags);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "landlock_restrict_self: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_landlock_abi_version_raw(long long cap) {
  OoResI r;
  oo_cap_require_sys(cap, "landlock_abi_version");
  r.ok = 0; r.val = -1;
  int v = (int)syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (v < 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "landlock_abi_version: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = (long long)v;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_seccomp_apply_raw(long long cap, OoStr filter_blob) {
  OoResI r;
  oo_cap_require_sys(cap, "seccomp_apply");
  r.ok = 0; r.val = -1;
  if (!filter_blob.data || filter_blob.len % (long long)sizeof(struct sock_filter) != 0) {
    r.err = oo_str_lit("seccomp_apply: invalid filter size");
    return r;
  }
  struct sock_fprog prog;
  prog.len = (unsigned short)(filter_blob.len / sizeof(struct sock_filter));
  prog.filter = (struct sock_filter *)filter_blob.data;
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "seccomp_apply: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}
