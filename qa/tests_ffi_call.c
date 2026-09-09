/* qa/tests_ffi_call.c — oo_ffi_call value/arg protocol + fail-closed rows.
 *
 * Covers: int/uint/long/ptr/void/string calling through forged sym tokens
 * (no dlopen policy involved), 0- and 6-arg arity, range rejections,
 * malformed specs/tokens/argv, and cap=0 in a forked child (must exit
 * nonzero before touching any pointer).
 *
 * Exit codes: 0 — all rows pass. 1 — any row fails.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../oodar.h"
#include "../types/types_str.h"

long long oo_cap_grant_ffi(void);
OoResS oo_ffi_call(long long cap, OoStr sym, OoStr rspec, OoStr aspec, OoStr argv);

static long long t_add2(long long a, long long b) { return a + b; }
static long long t_sum6(long long a, long long b, long long c,
                        long long d, long long e, long long f) {
  return a + b + c + d + e + f;
}
static long long t_const(void) { return 42; }
static void *t_idp(void *p) { return p; }
static int t_seen = 0;
static void t_mark(void) { t_seen = 7; }

static int fails = 0;

static OoStr S(const char *s) { return oo_str_lit(s); }

static void symtok(void *fn, char *buf, size_t n) {
  snprintf(buf, n, "sym:%p", fn);
}

/* Call and require ok=1 with exact val. Returns 1 on pass. */
static int expect_ok(long long cap, const char *sym, const char *rspec,
                     const char *aspec, const char *argv, const char *want) {
  OoResS r = oo_ffi_call(cap, S(sym), S(rspec), S(aspec), S(argv));
  size_t wn = strlen(want);
  if (!r.ok) {
    printf("FAIL ok expected: sym=%s rspec=%s aspec=%s argv=%s\n",
           sym, rspec, aspec, argv);
    return 0;
  }
  if ((size_t)r.val.len != wn || memcmp(r.val.data, want, wn) != 0) {
    printf("FAIL val: got [%.*s] want [%s]\n", (int)r.val.len,
           r.val.data ? r.val.data : "", want);
    return 0;
  }
  return 1;
}

/* Call and require ok=0 (fail-closed, no crash). Returns 1 on pass. */
static int expect_err(long long cap, const char *sym, const char *rspec,
                      const char *aspec, const char *argv) {
  OoResS r = oo_ffi_call(cap, S(sym), S(rspec), S(aspec), S(argv));
  if (r.ok) {
    printf("FAIL err expected: sym=%s rspec=%s aspec=%s argv=%s\n",
           sym, rspec, aspec, argv);
    return 0;
  }
  return 1;
}

static void run_cap_child(long long *leaked) {
  pid_t pid = fork();
  if (pid == 0) {
    OoResS r = oo_ffi_call(0, S("sym:0x1"), S("i"), S(""), S(""));
    (void)r;
    _exit(0);
  }
  {
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) *leaked = 1;
  }
}

int main(void) {
  long long cap = oo_cap_grant_ffi();
  char b_add[32], b_sum[32], b_const[32], b_idp[32], b_mark[32], b_strlen[32];
  long long leaked = 0;
  symtok((void *)(intptr_t)t_add2, b_add, sizeof b_add);
  symtok((void *)(intptr_t)t_sum6, b_sum, sizeof b_sum);
  symtok((void *)(intptr_t)t_const, b_const, sizeof b_const);
  symtok((void *)(intptr_t)t_idp, b_idp, sizeof b_idp);
  symtok((void *)(intptr_t)t_mark, b_mark, sizeof b_mark);
  symtok((void *)(intptr_t)strlen, b_strlen, sizeof b_strlen);

  fails += !expect_ok(cap, b_add, "i", "ii", "40\t2", "42");
  fails += !expect_ok(cap, b_sum, "i", "iiiiii", "1\t2\t3\t4\t5\t6", "21");
  fails += !expect_ok(cap, b_const, "i", "", "", "42");
  fails += !expect_ok(cap, b_strlen, "i", "s", "hello", "5");
  fails += !expect_ok(cap, b_add, "l", "ll", "4000000000\t2", "4000000002");
  fails += !expect_ok(cap, b_add, "u", "uu", "4294967295\t0", "4294967295");
  {
    /* Pointer round-trip: feed the returned token straight back in. */
    OoResS r = oo_ffi_call(cap, S(b_idp), S("p"), S("p"), S(b_add));
    char back[160];
    if (!r.ok) {
      printf("FAIL ptr call\n");
      fails++;
    } else {
      snprintf(back, sizeof back, "%.*s", (int)r.val.len, r.val.data);
      {
        char want[32];
        snprintf(want, sizeof want, "ptr:%s", b_add + 4);
        fails += !expect_ok(cap, b_idp, "p", "p", back, want);
      }
    }
  }
  t_seen = 0;
  fails += !expect_ok(cap, b_mark, "v", "", "", "");
  if (t_seen != 7) {
    printf("FAIL void call had no effect\n");
    fails++;
  }
  fails += !expect_err(cap, "bogus", "i", "", "");
  fails += !expect_err(cap, "sym:0x0", "i", "", "");
  fails += !expect_err(cap, b_add, "z", "ii", "1\t2");
  fails += !expect_err(cap, b_add, "i", "xy", "1\t2");
  fails += !expect_err(cap, b_add, "i", "ii", "1");
  fails += !expect_err(cap, b_add, "i", "ii", "1\t2\t3");
  fails += !expect_err(cap, b_add, "i", "i", "4x");
  fails += !expect_err(cap, b_add, "i", "i", "2147483648");
  fails += !expect_err(cap, b_add, "u", "u", "-1");
  fails += !expect_err(cap, b_add, "u", "u", "4294967296");
  fails += !expect_err(cap, b_add, "i", "p", "ptr:zzz");
  fails += !expect_err(cap, b_add, "i", "iiiiiii", "1\t2\t3\t4\t5\t6\t7");
  run_cap_child(&leaked);
  if (leaked) {
    printf("FAIL cap=0 call escaped\n");
    fails++;
  }
  if (fails == 0) printf("FFI_CALL_OK\n");
  return fails != 0;
}
