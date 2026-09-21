/* # oodar/qa/tests_overhaul_arena.c — Scoped Bump Arena Tests
 * Logline: Tier 1 & 2 tests for bump arena resets, allocations & bounds.
 * Setup: Validates oo_arena_create, alloc, reset, destroy, fail-closed caps.
 * Beats: 1. Lifecycle; 2. Reset offset 0; 3. Re-alloc; 4. Bounds & caps. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../oodar.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, name) do { \
  if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
  else { g_fail++; printf("  [FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

static long long get_arena_cap(void) {
  return oo_cap_grant_arena();
}

static void test_tier1_feature_coverage(void) {
  printf("--- Tier 1: Scoped Bump Arena Feature Coverage ---\n");
  long long cap = get_arena_cap();

  /* Case 1: Create arena with 4096 bytes */
  OoResS cr = oo_arena_create(cap, 4096);
  CHECK(cr.ok == 1, "arena_create_success");
  long long arena_id = cr.ok ? atoll(cr.val.data) : -1;
  CHECK(arena_id >= 0, "arena_id_valid");

  /* Case 2: Allocate chunks, verifying monotonic offset advance */
  OoResS a1 = oo_arena_alloc(cap, arena_id, 128);
  CHECK(a1.ok == 1, "arena_alloc_128_ok");
  long long off1 = a1.ok ? atoll(a1.val.data) : -1;
  CHECK(off1 == 0, "first_alloc_offset_zero");

  OoResS a2 = oo_arena_alloc(cap, arena_id, 256);
  CHECK(a2.ok == 1, "arena_alloc_256_ok");
  long long off2 = a2.ok ? atoll(a2.val.data) : -1;
  CHECK(off2 == 128, "second_alloc_offset_128");

  /* Case 3: Reset arena, verifying offset returns to 0 in O(1) */
  OoResS res = oo_arena_reset(cap, arena_id);
  CHECK(res.ok == 1, "arena_reset_success");

  /* Case 4: Subsequent allocation starts from offset 0 again */
  OoResS a3 = oo_arena_alloc(cap, arena_id, 64);
  CHECK(a3.ok == 1, "arena_alloc_after_reset_ok");
  long long off3 = a3.ok ? atoll(a3.val.data) : -1;
  CHECK(off3 == 0, "reused_alloc_offset_zero");

  /* Case 5: Destroy arena cleanly */
  OoResS des = oo_arena_destroy(cap, arena_id);
  CHECK(des.ok == 1, "arena_destroy_success");
}

static void test_tier2_boundary_cases(void) {
  printf("--- Tier 2: Scoped Bump Arena Boundary & Corner Cases ---\n");
  long long cap = get_arena_cap();

  /* Case 6: Reset on empty arena (offset 0) */
  OoResS c2 = oo_arena_create(cap, 1024);
  CHECK(c2.ok == 1, "arena_create_empty_ok");
  long long id2 = c2.ok ? atoll(c2.val.data) : -1;
  OoResS r_empty = oo_arena_reset(cap, id2);
  CHECK(r_empty.ok == 1, "reset_empty_arena_success");

  /* Case 7: Allocating beyond capacity fails closed without crash */
  OoResS oob = oo_arena_alloc(cap, id2, 2048);
  CHECK(oob.ok == 0, "alloc_exceeding_capacity_fails");

  /* Case 8: Bad size (< 64 bytes) fails */
  OoResS bad_sz = oo_arena_create(cap, 16);
  CHECK(bad_sz.ok == 0, "create_too_small_fails");

  /* Case 9: Invalid arena ID fails */
  OoResS bad_id = oo_arena_reset(cap, 999);
  CHECK(bad_id.ok == 0, "reset_invalid_id_fails");

  /* Case 10: Destroy arena cleans up */
  oo_arena_destroy(cap, id2);

  /* Case 11: Forged capability check via child fork (must abort) */
  pid_t pid = fork();
  if (pid == 0) {
    /* Child: pass forged cap 0x12345678, should fail closed */
    close(2); /* silence stderr */
    oo_arena_create(0x12345678LL, 1024);
    _exit(0); /* if we got here without aborting, test failed */
  }
  int st = 0;
  waitpid(pid, &st, 0);
  CHECK(WIFEXITED(st) && WEXITSTATUS(st) != 0, "forged_cap_fails_closed");

  /* Case 12: Multiple create-reset cycles stability */
  int cycles_ok = 1;
  for (int i = 0; i < 20; i++) {
    OoResS loop_cr = oo_arena_create(cap, 512);
    if (!loop_cr.ok) { cycles_ok = 0; break; }
    long long lid = atoll(loop_cr.val.data);
    oo_arena_alloc(cap, lid, 256);
    oo_arena_reset(cap, lid);
    oo_arena_alloc(cap, lid, 256);
    oo_arena_destroy(cap, lid);
  }
  CHECK(cycles_ok == 1, "rapid_arena_lifecycle_stable");
}

int main(void) {
  printf("=== openOODA QA: Scoped Bump Arena Tests ===\n");
  test_tier1_feature_coverage();
  test_tier2_boundary_cases();
  printf("Results: %d passed, %d failed\n", g_pass, g_fail);
  return (g_fail == 0) ? 0 : 1;
}
