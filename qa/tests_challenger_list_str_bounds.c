/* qa/tests_challenger_list_str_bounds.c — Defined bounds behavior, probed.
 *
 * Every core list/string op falls in one of two classes. There is no
 * third behavior (no UB, no silent wrap):
 *
 *   SENTINEL (non-fatal, caller checks the return):
 *     oo_byte_at / oo_str_byte_at OOB ............ -1
 *     oo_bytes_get OOB ........................... -1
 *     oo_bytes_push v<0 -> 0, v>255 -> 255 (clamp)
 *     oo_byte_slice .............................. clamp lo/hi, empty on
 *       start>end / start>=len / !data (never aborts)
 *     oo_str_slice ............................... strict: start<0,
 *       end<start, start>len -> empty (DIFFERS from byte_slice clamp)
 *     oo_str_index_of miss / bad args ............ -1 (empty needle -> 0)
 *     oo_str_contains/starts_with/ends_with ...... empty needle -> 1,
 *       oversize -> 0
 *     oo_str_repeat n<0 -> empty; n>1024 -> 1024 (cap)
 *     oo_str_concat/concat_list/concat_multi ..... empty parts skipped,
 *       all-empty -> empty
 *     oo_str_xor_lit !p / n<=0 / n>2^28 .......... empty
 *     oo_chr cp<0 / cp>255 ....................... NUL intern (len 1)
 *     oo_char_is_digit/alpha/space len!=1 ........ 0
 *     str_split empty delim -> 1-elem; empty s -> empty list
 *     oo_str_trim / str_trim all-space / empty ... empty
 *     oo_str_to_lowercase/uppercase empty ........ empty
 *     oo_str_intern_bytes !p / n<=0 .............. empty
 *     oo_ilist/slist/flist_slice ................. clamp lo/hi like
 *       byte_slice; lo>=hi -> empty (never aborts)
 *     oo_ll_I/ll_S_slice ......................... same clamp
 *     (oo_ll_F / oo_lll_* / oo_llll_* have no slice op)
 *
 *   FATAL (fail-closed: stderr + exit(1), probed in forked children):
 *     oo_ilist/slist/flist_get OOB, _set OOB
 *     oo_char_at OOB (char index, not byte index)
 *     oo_ll_I/S/F_get/set OOB, oo_lll_I/S/F_get OOB,
 *       oo_llll_I/S/F_get OOB
 *
 * Exit codes: 0 = all probes pass; 1 = at least one failed.
 * Output is fully deterministic (no PIDs, no timing) for double-run.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../oodar.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { fprintf(stderr, "FAIL\tbounds\t%s (line %d)\n", msg, __LINE__); g_fail++; } \
} while (0)

static int streq(OoStr s, const char *c) {
  size_t n = strlen(c);
  return s.len == (long long)n && memcmp(s.data, c, n) == 0;
}

/* --- Section A: sentinel (non-fatal) bounds, asserted in-process --- */
static void probe_sentinels(void) {
  OoStr abc = oo_str_lit("abc"), hello = oo_str_lit("hello");
  CHECK(oo_byte_at(abc, -1) == -1, "byte_at neg -> -1");
  CHECK(oo_byte_at(abc, 3) == -1, "byte_at len -> -1");
  CHECK(oo_str_byte_at(abc, 1) == 'b', "str_byte_at hit");
  CHECK(oo_str_index_of(hello, oo_str_lit("z")) == -1, "index_of miss -> -1");
  CHECK(oo_str_index_of(hello, oo_str_lit("")) == 0, "index_of empty -> 0");
  CHECK(oo_str_contains(hello, oo_str_lit("")) == 1, "contains empty -> 1");
  CHECK(oo_str_starts_with(hello, oo_str_lit("")) == 1, "starts empty -> 1");
  CHECK(oo_str_ends_with(hello, oo_str_lit("longer-than-hay")) == 0, "ends oversize -> 0");
  CHECK(streq(oo_byte_slice(hello, -2, 99), "hello"), "byte_slice clamps");
  CHECK(oo_byte_slice(hello, 3, 3).len == 0, "byte_slice empty range");
  CHECK(oo_byte_slice(hello, 4, 2).len == 0, "byte_slice start>end empty");
  CHECK(streq(oo_byte_slice(hello, 1, 4), "ell"), "byte_slice hit");
  CHECK(oo_str_slice(abc, -1, 1).len == 0, "str_slice neg start empty");
  CHECK(oo_str_slice(abc, 5, 9).len == 0, "str_slice past end empty");
  CHECK(oo_str_slice(abc, 2, 1).len == 0, "str_slice end<start empty");
  CHECK(streq(oo_str_slice(hello, 1, 4), "ell"), "str_slice hit");
  CHECK(oo_str_repeat(oo_str_lit("ab"), -3).len == 0, "repeat neg empty");
  CHECK(oo_str_repeat(oo_str_lit("a"), 5000).len == 1024, "repeat capped 1024");
  CHECK(oo_char_is_digit(oo_str_lit("5")) == 1, "is_digit hit");
  CHECK(oo_char_is_digit(oo_str_lit("ab")) == 0, "is_digit len!=1 -> 0");
  CHECK(oo_char_is_alpha(oo_str_lit("")) == 0, "is_alpha empty -> 0");
  CHECK(oo_chr(65).len == 1 && oo_chr(65).data[0] == 'A', "chr hit");
  CHECK(oo_chr(999).len == 1, "chr OOB -> NUL intern");
  CHECK(oo_str_xor_lit(NULL, 0, 7).len == 0, "xor_lit bad args empty");
  CHECK(streq(str_trim(oo_str_lit("  x  ")), "x"), "str_trim hit");
  CHECK(str_trim(oo_str_lit("")).len == 0, "str_trim empty");
  CHECK(streq(oo_str_to_lowercase(oo_str_lit("aB")), "ab"), "lower hit");
  CHECK(streq(oo_str_to_uppercase(oo_str_lit("aB")), "AB"), "upper hit");
  CHECK(streq(oo_int_to_str(42), "42"), "int_to_str hit");
  CHECK(streq(oo_str_concat(abc, oo_str_lit("")), "abc"), "concat empty part");
  CHECK(streq(oo_bytes_concat(abc, oo_str_lit("d")), "abcd"), "bytes_concat");
  CHECK(streq(oo_bytes_from_str(abc), "abc"), "bytes_from_str");
  OoSList sp = str_split(oo_str_lit("a,b"), oo_str_lit(","));
  CHECK(oo_slist_len(sp) == 2, "split hit len 2");
  oo_slist_release(sp);
  OoSList sp1 = str_split(oo_str_lit("abc"), oo_str_lit(""));
  CHECK(oo_slist_len(sp1) == 1, "split empty delim -> 1 elem");
  oo_slist_release(sp1);
  OoSList sp0 = str_split(oo_str_lit(""), oo_str_lit(","));
  CHECK(oo_slist_len(sp0) == 0, "split empty s -> empty");
  oo_slist_release(sp0);
  OoIList bl = oo_bytes_push(oo_bytes_push(oo_bytes_new(), 300), -5);
  CHECK(oo_bytes_get(bl, 0) == 255, "bytes_push clamps hi");
  CHECK(oo_bytes_get(bl, 1) == 0, "bytes_push clamps lo");
  CHECK(oo_bytes_get(bl, 9) == -1, "bytes_get OOB -> -1");
  OoStr bs = oo_bytes_to_str(bl);
  CHECK(bs.len == 2 && (unsigned char)bs.data[0] == 255 && bs.data[1] == 0, "bytes_to_str hit");
  oo_ilist_release(bl);
  OoIList il = oo_ilist_push(oo_ilist_push(oo_ilist_push(oo_ilist_new(), 10), 20), 30);
  CHECK(oo_ilist_slice(il, -5, 99).len == 3, "ilist_slice clamps");
  CHECK(oo_ilist_slice(il, 2, 2).len == 0, "ilist_slice empty range");
  CHECK(oo_ilist_slice(il, 5, 9).len == 0, "ilist_slice past end empty");
  oo_ilist_release(il);
  OoSList sl = oo_slist_push(oo_slist_new(), abc);
  CHECK(oo_slist_slice(sl, 0, 99).len == 1, "slist_slice clamps");
  oo_slist_release(sl);
  OoFList fl = oo_flist_push(oo_flist_new(), 1.5);
  CHECK(oo_flist_slice(fl, 1, 0).len == 0, "flist_slice lo>hi empty");
  oo_flist_release(fl);
  OoLL_I nll = oo_ll_I_push(oo_ll_I_new(), oo_ilist_new());
  CHECK(oo_ll_I_slice(nll, 0, 7).len == 1, "ll_I_slice clamps");
  oo_ll_I_release(nll);
}

/* --- Section B: fatal (fail-closed) bounds, one fork per op --- */
enum { F_ILIST_GET, F_SLIST_GET, F_FLIST_GET, F_ILIST_SET, F_SLIST_SET,
       F_FLIST_SET, F_CHAR_AT, F_LL_I_GET, F_LL_S_GET, F_LL_F_GET,
       F_LL_I_SET, F_LLL_I_GET, F_LLL_S_GET, F_LLL_F_GET, F_LLLL_I_GET,
       F_LLLL_S_GET, F_LLLL_F_GET, F_N };
static void fatal_child(int op) {
  switch (op) {
    case F_ILIST_GET: (void)oo_ilist_get(oo_ilist_new(), 0); break;
    case F_SLIST_GET: (void)oo_slist_get(oo_slist_new(), 0); break;
    case F_FLIST_GET: (void)oo_flist_get(oo_flist_new(), 0); break;
    case F_ILIST_SET: (void)oo_ilist_set(oo_ilist_new(), 0, 1); break;
    case F_SLIST_SET: (void)oo_slist_set(oo_slist_new(), 0, oo_str_lit("x")); break;
    case F_FLIST_SET: (void)oo_flist_set(oo_flist_new(), 0, 1.0); break;
    case F_CHAR_AT: (void)oo_char_at(oo_str_lit("ab"), 5); break;
    case F_LL_I_GET: (void)oo_ll_I_get(oo_ll_I_new(), 0); break;
    case F_LL_S_GET: (void)oo_ll_S_get(oo_ll_S_new(), 0); break;
    case F_LL_F_GET: (void)oo_ll_F_get(oo_ll_F_new(), 0); break;
    case F_LL_I_SET: (void)oo_ll_I_set(oo_ll_I_new(), 0, oo_ilist_new()); break;
    case F_LLL_I_GET: (void)oo_lll_I_get(oo_lll_I_new(), 0); break;
    case F_LLL_S_GET: (void)oo_lll_S_get(oo_lll_S_new(), 0); break;
    case F_LLL_F_GET: (void)oo_lll_F_get(oo_lll_F_new(), 0); break;
    case F_LLLL_I_GET: (void)oo_llll_I_get(oo_llll_I_new(), 0); break;
    case F_LLLL_S_GET: (void)oo_llll_S_get(oo_llll_S_new(), 0); break;
    default: (void)oo_llll_F_get(oo_llll_F_new(), 0); break;
  }
  _exit(7); /* op did not abort: probe failure */
}
static const char *g_names[F_N] = { "ilist_get", "slist_get", "flist_get",
  "ilist_set", "slist_set", "flist_set", "char_at", "ll_I_get", "ll_S_get",
  "ll_F_get", "ll_I_set", "lll_I_get", "lll_S_get", "lll_F_get", "llll_I_get",
  "llll_S_get", "llll_F_get" };
static void probe_fatals(void) {
  for (int op = 0; op < F_N; op++) {
    fflush(stdout); fflush(stderr);
    pid_t p = fork();
    if (p == 0) { fatal_child(op); _exit(7); }
    int st = 0;
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 1, g_names[op]);
  }
}

int main(void) {
  printf("bounds: starting (sentinels + %d fatal ops)\n", F_N);
  probe_sentinels();
  probe_fatals();
  if (g_fail) { fprintf(stderr, "FAIL bounds: %d failures\n", g_fail); return 1; }
  printf("OK\tbounds\tdefined+probed list/string OOB contract\n");
  return 0;
}
