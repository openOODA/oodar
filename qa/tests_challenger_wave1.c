/* qa/tests_challenger_wave1.c — Wave 1 hostile probes.
 * 1. oo_slist_new must not install seccomp / stamp Landlock.
 * 2. oo_sandbox_apply(cap=0) must fail closed.
 * 3. HMAC/hash reject negative OoStr.len (no wrap, no crash).
 * 4. Public oodar.h must not declare the OS helper symbols.
 * Exit 0 only if every probe fails closed. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include "../oodar.h"
#include "../sec/crypto/crypto_internal.h"

static int fail;

static int child_apply_zero(void) {
  pid_t p = fork();
  if (p < 0) return 0;
  if (p == 0) {
    alarm(2);
    (void)oo_sandbox_apply(0);
    _exit(0);
  }
  int st = 0;
  waitpid(p, &st, 0);
  return WIFEXITED(st) && WEXITSTATUS(st) != 0;
}

static int header_hides(const char *sym) {
  FILE *f = fopen("oodar.h", "r");
  char buf[512];
  if (!f) {
    const char *r = getenv("OODAR_REPO");
    char path[1024];
    if (!r) return 0;
    snprintf(path, sizeof path, "%s/oodar.h", r);
    f = fopen(path, "r");
    if (!f) return 0;
  }
  while (fgets(buf, sizeof buf, f)) {
    if (strstr(buf, sym) && strstr(buf, ";")) {
      fclose(f);
      return 0;
    }
  }
  fclose(f);
  return 1;
}

int main(void) {
  oo_sandbox_status_t st;
  OoSList l;
  int fd;
  OoStr bad;
  OoStr key;
  OoStr out;

  l = oo_slist_new();
  (void)l;
  st = oo_sandbox_status();
  if (st.is_enforced || st.backend == OO_SANDBOX_BACKEND_LINUX_LANDLOCK_SECCOMP) {
    fprintf(stderr, "FAIL\twave1\tslist_new stamped sandbox backend=%d enforced=%d\n",
            (int)st.backend, st.is_enforced);
    fail = 1;
  } else {
    printf("OK\twave1\tslist_new does not apply sandbox\n");
  }

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf(stderr, "FAIL\twave1\tsocket after slist_new errno=%d\n", errno);
    fail = 1;
  } else {
    close(fd);
    printf("OK\twave1\tsocket after slist_new still works\n");
  }

  if (child_apply_zero()) {
    printf("OK\twave1\too_sandbox_apply(0) fail-closed\n");
  } else {
    fprintf(stderr, "FAIL\twave1\too_sandbox_apply(0) leaked\n");
    fail = 1;
  }

  bad.data = "x";
  bad.len = -1;
  key.data = "k";
  key.len = 1;
  out = crypto_hmac_sha256_internal(key, bad);
  if (out.len != 0) {
    fprintf(stderr, "FAIL\twave1\thmac negative len returned len=%lld\n", out.len);
    fail = 1;
  } else {
    printf("OK\twave1\thmac negative len fail-closed\n");
  }
  out = crypto_sha256_internal(bad);
  if (out.len != 0) {
    fprintf(stderr, "FAIL\twave1\tsha256 negative len returned len=%lld\n", out.len);
    fail = 1;
  } else {
    printf("OK\twave1\tsha256 negative len fail-closed\n");
  }

  if (!header_hides("oo_process_policy_getenv") ||
      !header_hides("oo_child_filter_env") ||
      !header_hides("ffi_verify_signature") ||
      !header_hides("path_under_allowdir") ||
      !header_hides("path_under_sys_lib")) {
    fprintf(stderr, "FAIL\twave1\tOS helpers still declared in oodar.h\n");
    fail = 1;
  } else {
    printf("OK\twave1\tOS helpers unexported from oodar.h\n");
  }

  if (fail) {
    fprintf(stderr, "FAIL\twave1\thostile probes found an open path\n");
    return 1;
  }
  printf("PASS\twave1\tall Wave 1 probes fail-closed\n");
  return 0;
}
