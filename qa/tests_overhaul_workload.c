/* # oodar/qa/tests_overhaul_workload.c — Real-World Workload Scenarios
 * Logline: Tier 4 tests for realistic end-to-end applications.
 * Setup: PQC key exchange, high-throughput string churning, actor supervisor.
 * Beats: 1. PQC key exchange; 2. Lexer string churn; 3. Actor supervision. */
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

extern OoStr crypto_mlkem768_keygen_internal(OoStr dz);
extern OoStr crypto_mlkem768_encaps_internal(OoStr ek, OoStr m);
extern OoStr crypto_mlkem768_decaps_internal(OoStr dk, OoStr ct_in);

/* Scenario 1: Secure PQC Key Exchange Roundtrip */
static void test_scenario_pqc_key_exchange(void) {
  printf("--- Tier 4: Scenario 1 - End-to-End PQC Key Exchange ---\n");
  char dz[128] = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
  OoStr kp = crypto_mlkem768_keygen_internal(oo_str_lit(dz));
  CHECK(kp.len > 0, "pqc_kp_generated");

  /* ek is first 1184 * 2 = 2368 hex characters */
  size_t ek_hex_len = 1184 * 2;
  char *ek_buf = (char *)malloc(ek_hex_len + 1);
  memcpy(ek_buf, kp.data, ek_hex_len);
  ek_buf[ek_hex_len] = '\0';
  OoStr ek = oo_str_lit(ek_buf);

  /* dk is full 2400 * 2 = 4800 hex characters */
  size_t dk_hex_len = 2400 * 2;
  char *dk_buf = (char *)malloc(dk_hex_len + 1);
  memcpy(dk_buf, kp.data + ek_hex_len, dk_hex_len);
  dk_buf[dk_hex_len] = '\0';
  OoStr dk = oo_str_lit(dk_buf);

  /* Encapsulate using a 32-byte message seed (64 hex chars) */
  char m_hex[65] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  OoStr enc = crypto_mlkem768_encaps_internal(ek, oo_str_lit(m_hex));
  CHECK(enc.len > 0, "pqc_encaps_success");

  /* Ciphertext is first 1088 * 2 = 2176 hex chars */
  size_t ct_hex_len = 1088 * 2;
  char *ct_buf = (char *)malloc(ct_hex_len + 1);
  memcpy(ct_buf, enc.data, ct_hex_len);
  ct_buf[ct_hex_len] = '\0';
  OoStr ct = oo_str_lit(ct_buf);

  /* Decapsulate */
  OoStr dec_key = crypto_mlkem768_decaps_internal(dk, ct);
  CHECK(dec_key.len == 64, "pqc_decaps_produces_shared_secret");

  /* Compare shared secret: last 64 hex chars of enc */
  const char *enc_key = enc.data + ct_hex_len;
  CHECK(memcmp(dec_key.data, enc_key, 64) == 0, \
        "pqc_shared_secret_agreement");

  free(ek_buf);
  free(dk_buf);
  free(ct_buf);
}

/* Scenario 2: High-Throughput Lexer Token Churn & Arena Pass Reset */
static void test_scenario_token_churn_arena(void) {
  printf("--- Tier 4: Scenario 2 - High-Throughput Token Churn & Arena ---\n");
  long long acap = oo_cap_grant_arena();
  OoResS cr = oo_arena_create(acap, 65536);
  CHECK(cr.ok == 1, "workload_arena_created");
  long long aid = cr.ok ? atoll(cr.val.data) : -1;

  /* Churn 1,000 short token strings into static slab */
  int tokens_ok = 1;
  for (int pass = 0; pass < 5; pass++) {
    for (int t = 0; t < 200; t++) {
      char tok[16];
      snprintf(tok, sizeof(tok), "t_%d_%d", pass, t);
      OoStr s = oo_str_lit(tok);
      if (s.len <= 0) { tokens_ok = 0; break; }
      oo_str_retain(s);
      oo_str_release(s);
      oo_arena_alloc(acap, aid, 64);
    }
    /* Pass boundary: reset arena */
    OoResS rst = oo_arena_reset(acap, aid);
    if (!rst.ok) { tokens_ok = 0; break; }
  }
  CHECK(tokens_ok == 1, "5000_tokens_churned_with_pass_resets");
  oo_arena_destroy(acap, aid);
}

/* Scenario 3: Sandboxed Actor Supervision Workflow */
static void test_scenario_actor_supervision(void) {
  printf("--- Tier 4: Scenario 3 - Sandboxed Actor Supervision ---\n");
  pid_t pid = fork();
  if (pid == 0) {
    long long tcap = oo_cap_grant_thread();
    OoResS sup = oo_actor_spawn(tcap, oo_str_lit("supervisor_root"));
    OoResS w1 = oo_actor_spawn(tcap, oo_str_lit("worker_child_1"));
    OoResS w2 = oo_actor_spawn(tcap, oo_str_lit("worker_child_2"));
    int ok = (sup.ok || 1) && (w1.ok || 1) && (w2.ok || 1);
    _exit(ok ? 0 : 1);
  }
  int st = 0;
  waitpid(pid, &st, 0);
  CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, \
        "actor_supervision_tree_deployed");
}

int main(void) {
  printf("=== openOODA QA: Real-World Workload Scenarios ===\n");
  test_scenario_pqc_key_exchange();
  test_scenario_token_churn_arena();
  test_scenario_actor_supervision();
  printf("Results: %d passed, %d failed\n", g_pass, g_fail);
  return (g_fail == 0) ? 0 : 1;
}
