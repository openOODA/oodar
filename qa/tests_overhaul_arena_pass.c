/* # oodar/qa/tests_overhaul_arena_pass.c — Pass-scoped arena integration tests
 * Logline: Tier 1 & 2 tests for attach/detach, arena-backed lists, read-only
 * contains, checkpoint prune, and the slab/heap slice duality.
 * Setup: Uses oo_arena_create/alloc/reset/destroy plus oo_checkpoint/rollback.
 * Beats: 1. Attach/detach contract; 2. Arena list retain symmetry; 3. Slice
 * duality boundary; 4. Checkpoint/rollback lifecycle. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../oodar.h"

/* Internal membership query (fixed: read-only; the old body marked frames
 * dead via the free path). Declared here; defined in arena_checkpoint.c. */
extern int oo_arena_contains_ptr(const void *p);

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, name) do { \
  if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
  else { g_fail++; printf("  [FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

static long long acap(void) { return oo_cap_grant_arena(); }

static void test_attach_detach(void) {
  printf("--- Tier 1: Attach/detach contract ---\n");
  long long cap = acap();
  OoResS cr = oo_arena_create(cap, 8192);
  CHECK(cr.ok == 1, "pass_create_ok");
  long long id = cr.ok ? atoll(cr.val.data) : -1;
  CHECK(id >= 0, "pass_id_valid");
  /* n == 0 attaches; bad id fails closed. */
  OoResS at = oo_arena_alloc(cap, id, 0);
  CHECK(at.ok == 1, "pass_attach_ok");
  OoResS bad = oo_arena_alloc(cap, 999, 0);
  CHECK(bad.ok == 0, "pass_attach_bad_id_fails");
  /* n < 0 detaches; double detach stays OK (idempotent). */
  OoResS dt = oo_arena_alloc(cap, 0, -1);
  CHECK(dt.ok == 1, "pass_detach_ok");
  OoResS dt2 = oo_arena_alloc(cap, 0, -1);
  CHECK(dt2.ok == 1, "pass_detach_idempotent");
  OoResS des = oo_arena_destroy(cap, id);
  CHECK(des.ok == 1, "pass_destroy_ok");
}

static void test_arena_lists(void) {
  printf("--- Tier 1: Arena-backed lists + retain symmetry ---\n");
  long long cap = acap();
  OoResS cr = oo_arena_create(cap, 65536);
  CHECK(cr.ok == 1, "lists_create_ok");
  long long id = cr.ok ? atoll(cr.val.data) : -1;
  OoResS at = oo_arena_alloc(cap, id, 0);
  CHECK(at.ok == 1, "lists_attach_ok");
  OoIList l = oo_ilist_new();
  for (long long i = 0; i < 64; i++) {
    OoIList n = oo_ilist_push(l, i * 3);
    oo_ilist_release(l);
    l = n;
  }
  CHECK(oo_ilist_len(l) == 64, "lists_len_64");
  int vals_ok = 1;
  for (long long i = 0; i < 64; i++) {
    if (oo_ilist_get(l, i) != i * 3) { vals_ok = 0; break; }
  }
  CHECK(vals_ok, "lists_values_match");
  /* Retain/release must be symmetric no-ops on arena payloads: hammering
   * them must not inflate rc and pin every later push into COW copies. */
  for (int k = 0; k < 100; k++) {
    oo_ilist_retain(l);
    oo_ilist_release(l);
  }
  OoIList grown = oo_ilist_push(l, 999);
  CHECK(oo_ilist_len(grown) == 65 && oo_ilist_get(grown, 64) == 999,
      "lists_push_after_retain_hammer");
  oo_ilist_release(l);
  oo_ilist_release(grown);
  /* Membership is live while the arena lives, gone after destroy. */
  OoIList m = oo_ilist_new();
  m = oo_ilist_push(m, 7);
  CHECK(oo_arena_contains_ptr(m.data) == 1, "lists_contains_live");
  oo_ilist_release(m);
  CHECK(oo_arena_contains_ptr(m.data) == 1, "lists_contains_readonly");
  OoResS dt = oo_arena_alloc(cap, 0, -1);
  CHECK(dt.ok == 1, "lists_detach_ok");
  OoResS rs = oo_arena_reset(cap, id);
  CHECK(rs.ok == 1, "lists_reset_ok");
  OoResS des = oo_arena_destroy(cap, id);
  CHECK(des.ok == 1, "lists_destroy_ok");
  CHECK(oo_arena_contains_ptr(m.data) == 0, "lists_contains_dead");
}

static void test_slice_duality(void) {
  printf("--- Tier 1: Slice slab/heap duality ---\n");
  OoStr base = oo_str_lit("abcdefghijklmnopqrstuvwxyz0123456789");
  /* Short result (<=15) takes the slab path; 15/16 straddle the boundary. */
  OoStr s15 = oo_byte_slice(base, 0, 15);
  CHECK(s15.len == 15 && memcmp(s15.data, "abcdefghijklmno", 15) == 0,
      "slice_len15_slab");
  OoStr s16 = oo_byte_slice(base, 0, 16);
  CHECK(s16.len == 16 && memcmp(s16.data, "abcdefghijklmnop", 16) == 0,
      "slice_len16_heap");
  OoStr big = oo_byte_slice(base, 0, oo_bytes_len(base));
  CHECK(big.len == 36 && memcmp(big.data, base.data, 36) == 0,
      "slice_full_heap");
  OoStr empty = oo_byte_slice(base, 5, 5);
  CHECK(empty.len == 0, "slice_empty");
  OoStr clamp = oo_byte_slice(base, -4, 1000);
  CHECK(clamp.len == 36, "slice_clamp");
}

static void test_checkpoint_prune(void) {
  printf("--- Tier 2: Checkpoint/rollback lifecycle ---\n");
  long long cap = acap();
  OoResS cr = oo_arena_create(cap, 8192);
  CHECK(cr.ok == 1, "ckpt_create_ok");
  long long id = cr.ok ? atoll(cr.val.data) : -1;
  OoResS a1 = oo_arena_alloc(cap, id, 128);
  CHECK(a1.ok == 1, "ckpt_alloc_before");
  long long ck = oo_checkpoint(cap, id);
  CHECK(ck >= 0, "ckpt_push_ok");
  OoResS a2 = oo_arena_alloc(cap, id, 256);
  CHECK(a2.ok == 1, "ckpt_alloc_after");
  long long rb = oo_rollback(cap);
  CHECK(rb == id, "ckpt_rollback_id");
  /* Post-rollback alloc reuses the rewound region from offset 128. */
  OoResS a3 = oo_arena_alloc(cap, id, 64);
  long long off3 = a3.ok ? atoll(a3.val.data) : -1;
  CHECK(a3.ok == 1 && off3 == 128, "ckpt_reuse_after_rollback");
  OoResS des = oo_arena_destroy(cap, id);
  CHECK(des.ok == 1, "ckpt_destroy_ok");
  /* Empty-stack rollback is a safe no-op returning 0. */
  long long rb2 = oo_rollback(cap);
  CHECK(rb2 == 0, "ckpt_rollback_empty_zero");
}

int main(void) {
  printf("=== openOODA QA: Pass-Scoped Arena Integration Tests ===\n");
  test_attach_detach();
  test_arena_lists();
  test_slice_duality();
  test_checkpoint_prune();
  printf("Results: %d passed, %d failed\n", g_pass, g_fail);
  return (g_fail == 0) ? 0 : 1;
}
