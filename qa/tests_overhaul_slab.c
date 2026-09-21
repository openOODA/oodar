/* # oodar/qa/tests_overhaul_slab.c — Short-String Static Slab Tests
 * Logline: Tier 1 & 2 tests for string static slab (<= 15 B) & ARC.
 * Setup: Validates OO_FLAG_STATIC, retain/release no-op, boundaries.
 * Beats: 1. Flag test; 2. Retain no-op; 3. Release no-op; 4. Bounds. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "../oodar.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, name) do { \
  if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
  else { g_fail++; printf("  [FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

static OoStrHeader *get_hdr(OoStr s) {
  if (!s.data) return NULL;
  return ((OoStrHeader *)s.data) - 1;
}

static void test_tier1_feature_coverage(void) {
  printf("--- Tier 1: Static Slab Feature Coverage ---\n");
  /* Case 1: Short string <= 15 B has static flag */
  OoStr s1 = oo_str_lit("hello");
  OoStrHeader *h1 = get_hdr(s1);
  CHECK(h1 != NULL && (h1->flags & OO_FLAG_STATIC), "s1_has_static_flag");

  /* Case 2: Retain is no-op */
  uint32_t rc_before = h1 ? h1->ref_count : 0;
  oo_str_retain(s1);
  uint32_t rc_after = h1 ? h1->ref_count : 0;
  CHECK(rc_before == rc_after, "s1_retain_is_noop");

  /* Case 3: Release is no-op */
  oo_str_release(s1);
  CHECK(s1.data != NULL && s1.data[0] == 'h', "s1_release_is_noop");

  /* Case 4: Data pointer valid and null-terminated */
  CHECK(s1.len == 5 && strcmp(s1.data, "hello") == 0, "s1_data_valid");

  /* Case 5: Repeated interning returns consistent data */
  OoStr s2 = oo_str_lit("hello");
  CHECK(s2.len == 5 && strcmp(s2.data, s1.data) == 0, "s2_intern_identity");
}

static void test_tier2_boundary_cases(void) {
  printf("--- Tier 2: Static Slab Boundary & Corner Cases ---\n");
  /* Case 6: Empty string "" (0 bytes) */
  OoStr s_empty = oo_str_lit("");
  OoStrHeader *h_empty = get_hdr(s_empty);
  CHECK(s_empty.len == 0 && h_empty != NULL, "empty_str_len_zero");
  CHECK(h_empty && (h_empty->flags & OO_FLAG_STATIC), "empty_str_static");

  /* Case 7: 1-byte string */
  OoStr s_one = oo_str_lit("x");
  OoStrHeader *h_one = get_hdr(s_one);
  CHECK(s_one.len == 1 && s_one.data[0] == 'x', "one_byte_str_valid");
  CHECK(h_one && (h_one->flags & OO_FLAG_STATIC), "one_byte_str_static");

  /* Case 8: Exact 15-byte string threshold */
  OoStr s15 = oo_str_lit("123456789012345");
  OoStrHeader *h15 = get_hdr(s15);
  CHECK(s15.len == 15 && strcmp(s15.data, "123456789012345") == 0, \
        "exact_15_bytes_valid");
  CHECK(h15 && (h15->flags & OO_FLAG_STATIC), "exact_15_bytes_static");

  /* Case 9: 16-byte string (just over threshold) */
  OoStr s16 = oo_str_lit("1234567890123456");
  CHECK(s16.len == 16 && strcmp(s16.data, "1234567890123456") == 0, \
        "exact_16_bytes_valid");

  /* Case 10: Non-ASCII UTF-8 bytes within 15-byte limit */
  OoStr s_utf8 = oo_str_lit("h\xc3\xa9llo");
  CHECK(s_utf8.len > 0 && s_utf8.data != NULL, "utf8_short_intern_valid");

  /* Case 11: NULL pointer input handling */
  OoStr s_null = oo_str_lit(NULL);
  CHECK(s_null.len == 0 && s_null.data != NULL, "null_str_safe");
}

int main(void) {
  printf("=== openOODA QA: Short-String Slab & Invariant Test ===\n");
  test_tier1_feature_coverage();
  test_tier2_boundary_cases();
  printf("Results: %d passed, %d failed\n", g_pass, g_fail);
  return (g_fail == 0) ? 0 : 1;
}
