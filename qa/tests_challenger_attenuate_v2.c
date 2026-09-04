/* qa/tests_challenger_attenuate_v2.c — Rule 2 bitmask subset check.
 *
 * Round-5 deep-dive: the v2 attenuate API must enforce
 * SECURITY_MODEL.oot Rule 2 (parent_rights & child_rights ==
 * child_rights) before HMACing. The old API (oo_cap_attenuate)
 * cannot do this because the signature doesn't include
 * parent_rights; the v2 API fixes that.
 *
 * This test verifies the v2 function rejects every case where
 * the child requests rights the parent does not have, and
 * accepts every case where the child is a subset.
 *
 * The 4 round-4 CRITICALs (LCG fallbacks) would have been caught
 * by v3.2.2's differential test. The deferred CRITICAL #4
 * (Rule 2 bitmask check) is closed by this v3.3.0 contract.
 *
 * Exit codes:
 *   0 — all subset/superset cases behave correctly
 *   1 — a child with rights outside the parent's rights was accepted
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../oodar.h"
#include "../sec/cap/caps.h"

struct case_t {
  const char *name;
  const char *parent_rights;  /* hex */
  const char *child_rights;   /* hex */
  int expect_ok;             /* should v2 return non-empty (i.e., subset)? */
};

static struct case_t CASES[] = {
  /* Equal masks: should be accepted. */
  {"equal",                "ff",      "ff",      1},
  /* Subset: child < parent. */
  {"subset_singleton",     "ff",      "01",      1},
  {"subset_lo",            "ff",      "00",      1},
  {"subset_hi",            "ff",      "80",      1},
  /* Superset: child > parent. MUST BE REJECTED. */
  {"superset_one_bit",     "01",      "ff",      0},
  {"superset_different",   "0f",      "f0",      0},
  /* Empty: child=0 is always a subset. */
  {"child_zero",           "ff",      "00",      1},
  /* Child = parent for one bit. */
  {"single_bit_match",     "01",      "01",      1},
  /* Single bit, parent has it, child has different. */
  {"single_bit_diff",      "01",      "02",      0},
  {NULL, NULL, NULL, 0}
};

int main(void) {
  OoStr pm = oo_str_lit("0123456789abcdef0123456789abcdef");
  int failures = 0;
  for (int i = 0; CASES[i].name; i++) {
    OoStr pr = oo_str_lit(CASES[i].parent_rights);
    OoStr cr = oo_str_lit(CASES[i].child_rights);
    int ok = oo_cap_attenuate_v2_ok(pm, pr, cr);
    int expected = CASES[i].expect_ok;
    if (ok != expected) {
      fprintf(stderr, "FAIL\trule2\t%s: parent=0x%s child=0x%s: got ok=%d, want %d\n",
              CASES[i].name, CASES[i].parent_rights, CASES[i].child_rights, ok, expected);
      failures++;
    } else {
      fprintf(stderr, "OK\trule2\t%s: parent=0x%s child=0x%s: ok=%d (correct)\n",
              CASES[i].name, CASES[i].parent_rights, CASES[i].child_rights, ok);
    }
  }
  if (failures == 0) {
    printf("OK\trule2\t%d/%d Rule 2 cases pass (subset accepted, superset rejected)\n",
           (int)(sizeof(CASES)/sizeof(CASES[0]) - 1) - failures,
           (int)(sizeof(CASES)/sizeof(CASES[0]) - 1));
    return 0;
  }
  fprintf(stderr, "FAIL\trule2\t%d / %d cases wrong\n", failures, (int)(sizeof(CASES)/sizeof(CASES[0]) - 1));
  return 1;
}
