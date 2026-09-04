#include "../../../oodar.h"
#include "../landlock.h"
#include "../sandbox.h"
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

static OoResS ll_err(const char *msg) {
  return (OoResS){0, oo_str_lit(msg)};
}

static unsigned long long ll_handled_fs(int abi) {
  unsigned long long a = LL_FS_ABI1;
  if (abi >= 2) a |= LL_FS_REFER;
  if (abi >= 3) a |= LL_FS_TRUNCATE;
  if (abi >= 5) a |= LL_FS_IOCTL_DEV;
  return a;
}

static unsigned long long ll_read_bits(int abi) {
  (void)abi;
  return LL_FS_READ_FILE | LL_FS_READ_DIR;
}

static unsigned long long ll_write_bits(int abi) {
  unsigned long long a = LL_FS_WRITE_FILE | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE |
    LL_FS_MAKE_CHAR | LL_FS_MAKE_DIR | LL_FS_MAKE_REG | LL_FS_MAKE_SOCK |
    LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK | LL_FS_MAKE_SYM;
  a |= ll_read_bits(abi);
  if (abi >= 2) a |= LL_FS_REFER;
  if (abi >= 3) a |= LL_FS_TRUNCATE;
  return a;
}

/* Walk colon-separated absolute dirs. fn==NULL counts only. Returns 0 or negative error. */
static int ll_each_dir(OoStr dirs, int *count, int (*fn)(const char *, void *), void *ctx) {
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
      char buf[PATH_MAX];
      if (len >= PATH_MAX) return -2;
      memcpy(buf, p + start, (size_t)len);
      buf[len] = '\0';
      if (buf[0] != '/') return -3;
      if (fn && fn(buf, ctx) != 0) return -4;
      if (count) (*count)++;
    }
    if (i >= n) break;
    i++;
  }
  return 0;
}

#if defined(__NR_landlock_add_rule)
struct ll_add_ctx {
  int ruleset_fd;
  unsigned long long access;
};

static int ll_add_one(const char *path, void *v) {
  struct ll_add_ctx *c = (struct ll_add_ctx *)v;
  int fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return -1;
  struct landlock_path_beneath_attr attr;
  memset(&attr, 0, sizeof attr);
  attr.allowed_access = c->access;
  attr.parent_fd = fd;
  long rc = syscall(__NR_landlock_add_rule, c->ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
  close(fd);
  return rc == 0 ? 0 : -1;
}
#endif

OoResS oo_landlock_restrict(long long cap, OoStr read_dirs, OoStr write_dirs) {
  oo_cap_require_sys(cap, "landlock_restrict");
  int nread = 0, nwrite = 0;
  int pr = ll_each_dir(read_dirs, &nread, NULL, NULL);
  int pw = ll_each_dir(write_dirs, &nwrite, NULL, NULL);
  if (pr == -3 || pw == -3) return ll_err("ERR\tlandlock\tpath not absolute");
  if (pr == -2 || pw == -2) return ll_err("ERR\tlandlock\tpath too long");
  if (pr == -1 || pw == -1) return ll_err("ERR\tlandlock\tembedded NUL in path");
  if (pr != 0 || pw != 0) return ll_err("ERR\tlandlock\tinvalid path list");
  if (nread + nwrite > LL_MAX_DIRS) return ll_err("ERR\tlandlock\ttoo many paths");

  // Landlock is REQUIRED. We do NOT fall back to oo_sandbox_restrict_paths
  // (or any seccomp/matrix-only shim) — per project policy, fallbacks and
  // compatibility layers are removed. If Landlock is unavailable on this
  // kernel, the caller must probe oo_landlock_is_available() and refuse
  // to start. Refusing to fall back closes a class of side-channel escape
  // that would otherwise be possible on a system that has seccomp but not
  // Landlock, since the matrix-only path provides no path confinement.
#if !defined(__NR_landlock_create_ruleset)
  return ll_err("ERR\tlandlock\tnot_supported_on_this_kernel");
#else
  int abi = ll_abi_version();
  if (abi < 1) {
    return ll_err("ERR\tlandlock\tnot_supported_on_this_kernel");
  }

  struct landlock_ruleset_attr attr;
  memset(&attr, 0, sizeof attr);
  attr.handled_access_fs = ll_handled_fs(abi);
  size_t attr_sz = sizeof(attr.handled_access_fs);
  if (abi >= 4) attr_sz += sizeof(attr.handled_access_net);
  if (abi >= 6) attr_sz += sizeof(attr.scoped);

  int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &attr, attr_sz, 0);
  if (ruleset_fd < 0) return ll_err("ERR\tlandlock\tcreate_ruleset failed");

  /* GAP-10: If allowlist is empty (nread == 0 && nwrite == 0), 0 rules are added,
   * enforcing a total filesystem lockdown across the process. */
  if (nread > 0) {
    struct ll_add_ctx ctx;
    ctx.ruleset_fd = ruleset_fd;
    ctx.access = ll_read_bits(abi) & attr.handled_access_fs;
    if (ll_each_dir(read_dirs, NULL, ll_add_one, &ctx) != 0) {
      close(ruleset_fd);
      return ll_err("ERR\tlandlock\tadd_rule read path failed");
    }
  }
  if (nwrite > 0) {
    struct ll_add_ctx ctx;
    ctx.ruleset_fd = ruleset_fd;
    ctx.access = ll_write_bits(abi) & attr.handled_access_fs;
    if (ll_each_dir(write_dirs, NULL, ll_add_one, &ctx) != 0) {
      close(ruleset_fd);
      return ll_err("ERR\tlandlock\tadd_rule write path failed");
    }
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    close(ruleset_fd);
    return ll_err("ERR\tlandlock\tfailed to set PR_SET_NO_NEW_PRIVS");
  }
  if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
    close(ruleset_fd);
    return ll_err("ERR\tlandlock\trestrict_self failed");
  }
  close(ruleset_fd);
  oo_landlock_mark_applied(); /* v2.1.0: mark the ruleset as applied for proc_mem. */
  return (OoResS){1, oo_str_lit("OK_LANDLOCK_ENFORCED")};
#endif
}
