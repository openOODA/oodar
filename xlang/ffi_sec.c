/* M156/M162/M165: process-local UnsafeFFICap + allowlisted OS dlopen Path A.
 * Path A also: registered-handle dlsym/dlclose (no typed ffi_call of symbols). */
#include "../oodar.h"
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

static pthread_once_t g_ffi_once = PTHREAD_ONCE_INIT;
static long long g_tok_ffi;

static void ffi_once_init(void) {
  unsigned char b[8];
  size_t i;
  unsigned long long acc;
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(b, sizeof b) != 0) {
    /* Fail-closed: no LCG fallback. getentropy() must succeed for unpredictable FFI token. */
    fprintf(stderr, "ERR\tcap\tgetentropy() failed; refusing to derive FFI capability token\n");
    abort();
  }
#else
  /* Fail-closed: no LCG fallback. getentropy() is required. */
  fprintf(stderr, "ERR\tcap\tgetentropy() not available; refusing to derive FFI capability token\n");
  abort();
#endif
  {
    unsigned long long ent = ((((unsigned long long)b[0]) << 56) |
                              (((unsigned long long)b[1]) << 48) |
                              (((unsigned long long)b[2]) << 40) |
                              (((unsigned long long)b[3]) << 32) |
                              (((unsigned long long)b[4]) << 24) |
                              (((unsigned long long)b[5]) << 16) |
                              (((unsigned long long)b[6]) << 8)  |
                              ((unsigned long long)b[7])) & 0x00FFFFFFFFFFFFFFULL;
    g_tok_ffi = ((long long)(0x5 & 0x1F) << 56) | (long long)ent;
  }
  if (g_tok_ffi == 0x4F4F4649LL) g_tok_ffi ^= 0x11111111LL;
}

static void oo_ffi_init(void) {
  pthread_once(&g_ffi_once, ffi_once_init);
}

long long oo_cap_grant_ffi(void) {
  oo_ffi_init();
  return g_tok_ffi;
}

void oo_cap_require_ffi(long long got, const char *op) {
  oo_ffi_init();
  if (got != g_tok_ffi) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n",
            op ? op : "ffi");
    exit(1);
  }
}

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
