/* M156/M162/M165: process-local UnsafeFFICap + allowlisted OS dlopen Path A.
 * Path A also: registered-handle dlsym/dlclose (no typed ffi_call of symbols).
 *
 * v3.4.0 round-6: the FFICap subsystem (g_tok_ffi, oo_cap_grant_ffi,
 * oo_cap_require_ffi) moved to sec/cap/cap_ffi.c per the misplaced-
 * files audit. This file is now the dlopen signature + allowlist logic. */
#include "../../oodar.h"
#include "../../oodar_internal.h"
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

/* Canonical-path prefix allow: both inputs run through realpath and the
 * canonical paths are compared. Closes `..` traversal, symlink hops,
 * and case-insensitive FS games. */
int path_under_allowdir(const char *path, const char *dir) {
  char rp_path[PATH_MAX];
  char rp_dir[PATH_MAX];
  size_t n;
  if (!path || !dir || path[0] != '/' || dir[0] != '/') return 0;
  /* Reject root — operators who set "/" mean to allow everything; we refuse. */
  if (strcmp(dir, "/") == 0) return 0;
  if (!realpath(path, rp_path)) return 0;
  if (!realpath(dir, rp_dir)) return 0;
  n = strlen(rp_dir);
  if (n == 0 || strncmp(rp_path, rp_dir, n) != 0) return 0;
  if (rp_path[n] != '\0' && rp_path[n] != '/') return 0;
  return 1;
}

/* M165: safe system lib dirs when ALLOWDIR empty (not unrestricted any-path). */
int path_under_sys_lib(const char *path) {
  return path_under_allowdir(path, "/lib")
      || path_under_allowdir(path, "/lib64")
      || path_under_allowdir(path, "/usr/lib")
      || path_under_allowdir(path, "/usr/lib64");
}

/* M166 (fixes 6.5): require minisign signature on every .so loaded.
 * Trust anchor is the .pub at OO_FFI_PUBKEY_PATH + fingerprint
 * OO_FFI_PUBKEY_FP_DEFAULT. OODA_FFI_PUBKEY_FP env overrides fp for
 * roll-over; pattern mirrors oo_process_policy_getenv in ffi_once_init. */
#define OO_FFI_PUBKEY_PATH  "/etc/ooda/ffi.pub"
#define OO_FFI_PUBKEY_FP_DEFAULT \
  "0000000000000000000000000000000000000000000000000000000000000000"

/* Verify <path>.minisig adjacent via `minisign -V -p <pk> -m <path> -P <fp>`.
 * Returns 1 on valid signature matching expected fingerprint, 0 otherwise. */
int ffi_verify_signature(const char *path) {
  char sig[PATH_MAX];
  const char *pub_path = OO_FFI_PUBKEY_PATH;
  pid_t pid;
  int status;
  size_t path_len;
  const char *expected_fp;
  if (!path || !path[0]) return 0;
  path_len = strlen(path);
  if (path_len + 9 >= sizeof(sig)) return 0;
  snprintf(sig, sizeof(sig), "%s.minisig", path);
  if (access(sig, R_OK) != 0) return 0;
  if (access(pub_path, R_OK) != 0) return 0;
  expected_fp = oo_process_policy_getenv("OODA_FFI_PUBKEY_FP");
  if (!expected_fp || !expected_fp[0]) {
    expected_fp = OO_FFI_PUBKEY_FP_DEFAULT;
  }
  pid = fork();
  if (pid < 0) return 0;
  if (pid == 0) {
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, 0);
      dup2(devnull, 1);
      dup2(devnull, 2);
      if (devnull > 2) close(devnull);
    }
    oo_child_filter_env();
    execlp("minisign", "minisign", "-V",
           "-p", pub_path,
           "-m", path,
           "-x", sig,
           "-P", expected_fp,
           (char *)NULL);
    _exit(127);
  }
  if (waitpid(pid, &status, 0) < 0) return 0;
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
