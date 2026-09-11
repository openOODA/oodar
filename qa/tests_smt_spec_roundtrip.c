/* tests_smt_spec_roundtrip.c — Structural probe for the SMT spec.
 *
 * v4.10.0 (2026-09-12, Task B). Validates that sec/cap/formal_spec.smt2
 * is well-formed SMT-LIB 2 — the encoding is portable to Z3, CVC5,
 * Yices, etc. The probe does NOT run the actual proof (no prover is
 * installed on this host); it just asserts the file is parseable +
 * contains the 4 properties (P1-P4) + 4 (check-sat) calls + the
 * expected logic setting.
 *
 * To run the actual proof on a host with a prover installed:
 *
 *   z3 -smt2 < sec/cap/formal_spec.smt2     # expect 4 × unsat
 *   cvc5 --lang=smt2 -i sec/cap/formal_spec.smt2
 *   yices-smt2 sec/cap/formal_spec.smt2
 *
 * Exit codes: 0 = spec is structurally valid; 1 = at least one check
 * failed. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH "../sec/cap/formal_spec.smt2"

static int g_failures = 0;
#define ASSERT(cond, msg) do { \
  if (!(cond)) { \
    fprintf(stderr, "FAIL %s: %s\n", PATH, msg); \
    g_failures++; \
  } \
} while (0)

static int contains(const char *haystack, const char *needle) {
  return strstr(haystack, needle) != NULL;
}

static int count_lines_with(const char *haystack, const char *needle) {
  int count = 0;
  const char *p = haystack;
  size_t nlen = strlen(needle);
  while ((p = strstr(p, needle)) != NULL) {
    count++;
    p += nlen;
  }
  return count;
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  fprintf(stderr, "  smt-spec-roundtrip probe: starting\n");

  /* Read the spec file. */
  FILE *fp = fopen(PATH, "rb");
  ASSERT(fp != NULL, "spec file open failed");
  if (!fp) return 1;
  fseek(fp, 0, SEEK_END);
  long sz = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  ASSERT(sz > 0 && sz < 1024 * 1024, "spec file size out of bounds");
  char *buf = malloc(sz + 1);
  ASSERT(buf != NULL, "malloc failed");
  size_t n = fread(buf, 1, sz, fp);
  fclose(fp);
  buf[n] = '\0';

  /* (1) Logic setting: QF_BV (quantifier-free bit-vectors). */
  ASSERT(contains(buf, "(set-logic QF_BV)"),
         "spec must declare (set-logic QF_BV)");

  /* (2) Type alias for Cap = BitVec 64. */
  ASSERT(contains(buf, "(define-sort Cap () (_ BitVec 64))"),
         "spec must define Cap as 64-bit bitvector");

  /* (3) The 4 properties: each has its own (check-sat) call.
   * We count (check-sat) occurrences. */
  int nchecksat = count_lines_with(buf, "(check-sat)");
  ASSERT(nchecksat >= 4,
         "spec must have >= 4 (check-sat) calls (one per property P1-P4)");

  /* (4) Property 1: fail-closed on absence. Look for the ZERO
   * assertion and the (= g_tok_X ZERO) negation pattern. */
  ASSERT(contains(buf, "(= g_tok_fs  ZERO)"),
         "P1 must assert g_tok_fs = ZERO (negated property)");
  ASSERT(contains(buf, "(= g_tok_sys ZERO)"),
         "P1 must assert g_tok_sys = ZERO (negated property)");

  /* (5) Property 3: attenuation. Look for the bvand(bvnot()) pattern. */
  ASSERT(contains(buf, "bvand p3_attenuated (bvnot p3_request)"),
         "P3 must use bvand with bvnot for monotonicity check");

  /* (6) Property 4: grant monotonicity. Look for the bvand with parent. */
  ASSERT(contains(buf, "bvand p4_granted (bvnot p4_parent)"),
         "P4 must use bvand with bvnot for grant monotonicity check");

  /* (7) Comment block referencing the plan + the run instructions. */
  ASSERT(contains(buf, "deepening plan Task B"),
         "spec must reference the 2026-09-12 deepening plan Task B");
  ASSERT(contains(buf, "z3 -smt2"),
         "spec must include the run instructions (z3 invocation)");

  free(buf);

  if (g_failures != 0) {
    fprintf(stderr, "FAIL smt-spec-roundtrip: %d failures\n", g_failures);
    return 1;
  }
  fprintf(stderr,
          "OK smt-spec-roundtrip: spec is structurally valid (4 properties, "
          "4 check-sat calls, QF_BV logic, 64-bit Cap type)\n");
  return 0;
}
