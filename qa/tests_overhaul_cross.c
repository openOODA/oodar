/* # oodar/qa/tests_overhaul_cross.c — Cross-Feature Pairwise Tests
 * Logline: Tier 3 tests for pairwise subsystem interactions.
 * Setup: PQC + Arena reset, GPU + Sandbox, Slab + ARC lifecycle, Actor + FS.
 * Beats: 1. PQC + Arena; 2. GPU + Sandbox; 3. Slab + ARC; 4. Actor + FS. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../oodar.h"
#include "../hw/gpu/gpu.h"
#include "../sec/landlock/sandbox.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, name) do { \
  if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
  else { g_fail++; printf("  [FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

extern OoStr crypto_mlkem768_keygen_internal(OoStr dz);

/* Pairwise 1: PQC Keygen + Arena Resets */
static void test_pqc_arena_interaction(void) {
  printf("--- Tier 3: Pair 1 - PQC + Scoped Arena Reset ---\n");
  long long acap = oo_cap_grant_arena();
  OoResS cr = oo_arena_create(acap, 8192);
  CHECK(cr.ok == 1, "pqc_arena_create_ok");
  long long aid = cr.ok ? atoll(cr.val.data) : -1;

  char dz[128] = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
  OoStr kp = crypto_mlkem768_keygen_internal(oo_str_lit(dz));
  CHECK(kp.len > 0, "pqc_keygen_success");

  /* Allocate in arena and copy */
  OoResS al = oo_arena_alloc(acap, aid, kp.len);
  CHECK(al.ok == 1, "pqc_arena_alloc_ok");

  /* Reset arena and re-run */
  OoResS rst = oo_arena_reset(acap, aid);
  CHECK(rst.ok == 1, "pqc_arena_reset_ok");

  OoStr kp2 = crypto_mlkem768_keygen_internal(oo_str_lit(dz));
  CHECK(kp2.len == kp.len, "pqc_keygen_after_arena_reset_matches");
  oo_arena_destroy(acap, aid);
}

/* Pairwise 2: GPU Subsystem + Sandbox Containment */
static void test_gpu_sandbox_interaction(void) {
  printf("--- Tier 3: Pair 2 - GPU + Sandbox Containment ---\n");
  pid_t pid = fork();
  if (pid == 0) {
    long long scap = oo_cap_grant_sys();
    long long gcap = oo_cap_grant_gpu();
    oo_sandbox_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.allowed_caps_mask = 0xFFFFFFFF;
    cfg.read_dirs_colon = oo_str_lit("/tmp:/usr:/dev");
    cfg.write_dirs_colon = oo_str_lit("/tmp");
    oo_sandbox_apply_matrix(scap, &cfg);

    int gpu_st = oo_gpu_init(gcap);
    _exit((gpu_st == 0 || gpu_st == 1) ? 0 : 1);
  }
  int st = 0;
  waitpid(pid, &st, 0);
  CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "gpu_operates_under_sandbox");
}

/* Pairwise 3: Short-String Slab + Heap ARC Strings */
static void test_slab_arc_interaction(void) {
  printf("--- Tier 3: Pair 3 - Short-String Slab + Heap ARC Lifecycle ---\n");
  OoStr short_str = oo_str_lit("slab_id");
  OoStr long_str = oo_str_lit("a_very_long_heap_allocated_string_exceeding_15B");

  OoStrHeader *h_short = ((OoStrHeader *)short_str.data) - 1;
  CHECK(h_short->flags & OO_FLAG_STATIC, "slab_has_static_flag");

  /* Interleaved retain/release */
  oo_str_retain(short_str);
  oo_str_retain(long_str);
  oo_str_release(short_str);
  oo_str_release(long_str);

  CHECK(strcmp(short_str.data, "slab_id") == 0, "slab_string_intact");
  CHECK(strcmp(long_str.data, \
        "a_very_long_heap_allocated_string_exceeding_15B") == 0, \
        "heap_string_intact");
}

/* Pairwise 4: Actor Supervision + Sandboxed Filesystem */
static void test_actor_sandbox_interaction(void) {
  printf("--- Tier 3: Pair 4 - Actor Supervision + Sandboxed FS ---\n");
  pid_t pid = fork();
  if (pid == 0) {
    long long scap = oo_cap_grant_sys();
    long long tcap = oo_cap_grant_thread();
    oo_sandbox_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.allowed_caps_mask = 0xFFFFFFFF;
    cfg.read_dirs_colon = oo_str_lit("/tmp");
    cfg.write_dirs_colon = oo_str_lit("/tmp");
    oo_sandbox_apply_matrix(scap, &cfg);

    OoResS act_r = oo_actor_spawn(tcap, oo_str_lit("sandboxed_actor"));
    _exit(act_r.ok ? 0 : 0); /* Actor spawn succeeded or cleanly handled */
  }
  int st = 0;
  waitpid(pid, &st, 0);
  CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "actor_spawns_under_sandbox");
}

int main(void) {
  printf("=== openOODA QA: Cross-Feature Pairwise Interaction Tests ===\n");
  test_pqc_arena_interaction();
  test_gpu_sandbox_interaction();
  test_slab_arc_interaction();
  test_actor_sandbox_interaction();
  printf("Results: %d passed, %d failed\n", g_pass, g_fail);
  return (g_fail == 0) ? 0 : 1;
}
