/* qa/tests_challenger_exec_capture.c — oo_sys_exec captures >16MiB (regression).
 * `oodac build` captures `emit-llvm --concat` IR here; real programs emit
 * ~18MB. The old 16MiB cap truncated the pipe, SIGPIPE'd the child, and
 * failed the build. This asserts a 20MB capture arrives whole. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../oodar.h"
#include "../sec/cap/caps.h"

#define BIG_N (20000000L)

int main(void) {
  long long cap = oo_cap_grant_process();
  int fails = 0;

  OoStr small_av[2] = {oo_str_lit("/bin/echo"), oo_str_lit("hello")};
  OoResS small = oo_sys_exec(cap, 2, small_av);
  if (!small.ok || small.val.len != 6 ||
      memcmp(small.val.data, "hello\n", 6) != 0) {
    fprintf(stderr, "FAIL\texec_capture\tsmall echo: ok=%d len=%lld\n",
            small.ok, small.val.len);
    fails++;
  }

  OoStr big_av[4] = {oo_str_lit("/usr/bin/head"), oo_str_lit("-c"),
                     oo_str_lit("20000000"), oo_str_lit("/dev/zero")};
  if (access("/usr/bin/head", X_OK) != 0) {
    big_av[0] = oo_str_lit("/bin/head");
  }
  OoResS big = oo_sys_exec(cap, 4, big_av);
  if (!big.ok || big.val.len != BIG_N) {
    fprintf(stderr, "FAIL\texec_capture\t20MB: ok=%d len=%lld want=%ld\n",
            big.ok, big.val.len, BIG_N);
    fails++;
  }

  if (fails == 0) {
    printf("OK\texec_capture\t2/2 (20MB whole)\n");
    return 0;
  }
  return 1;
}
