/* oodar/sec/cap/cap_ocap_bridge.c — Memory-safe cap check via std OCap.
 *
 * Phase 1 of the std/sec/capability migration. The C-side bridge uses
 * the OCap records produced by std/sec/capability/ocap_to_oodar.oo
 * (compiled via oodac emit-c into scripts/build/cap_ocap_emitted.c)
 * to do structured-rights checks on every cap gate.
 *
 * Mapping: the 26 substrate caps (oodar's g_tok_*) map to the 20
 * NORTHSTAR language tokens (NORTHSTAR §1.4). The mapping table at
 * the bottom of this file is the source of truth. The substrate
 * tokens AUDIO/CAMERA/USB/HID/WINDOW/FRAME (6 future-state caps per
 * caps.h) don't have language tokens yet — they map to FsReadCap
 * for now per the substrate convention.
 *
 * The bridge is additive: existing callers don't change. Phase 2
 * routes one existing oo_cap_require_X gate through both paths and
 * requires agreement. Phase 3 routes the remaining 19 gates.
 */

#include "../../oodar.h"
#include "../../core/mem/safety.h"
#include "../landlock/sandbox.h"
#include <stddef.h>
#include <string.h>

/* Forward decls for the oodac-emitted C. The header is generated
 * per build by scripts/Makefile's emit-std-ocap target. */
extern OCapBridgeRecord ocap_to_oodar_record_for(OoStr name);
extern long long ocap_to_oodar_rights_for_name(OoStr name);
extern OoSList ocap_to_oodar_all_names(void);
extern int ocap_to_oodar_has_permission(OoStr name, long long required);

/* Mapping from oodar substrate cap (g_tok_* index) to language token
 * name. Substrate cap indices match the oo_cap_self_token ordering
 * (caps.c:173-180), with the 4 sub-store tokens (alloc/time/rand/ffi)
 * appended at indices 22-25. */
static const char *const SUBSTRATE_TO_LANGUAGE[26] = {
  /* 0  g_tok_fs        */ "FsCap",
  /* 1  g_tok_sys       */ "SysCap",
  /* 2  g_tok_env       */ "EnvCap",
  /* 3  g_tok_net       */ "NetCap",
  /* 4  g_tok_sign      */ "SignCap",
  /* 5  g_tok_process   */ "ProcessCap",
  /* 6  g_tok_tcp       */ "TcpCap",
  /* 7  g_tok_udp       */ "UdpCap",
  /* 8  g_tok_bind      */ "BindCap",
  /* 9  g_tok_audio     */ "FsReadCap",  /* substrate-only, no language token yet */
  /* 10 g_tok_camera    */ "FsReadCap",
  /* 11 g_tok_usb       */ "FsReadCap",
  /* 12 g_tok_hid       */ "FsReadCap",
  /* 13 g_tok_window    */ "FsReadCap",
  /* 14 g_tok_frame     */ "FsReadCap",
  /* 15 g_tok_fsread    */ "FsReadCap",
  /* 16 g_tok_fswrite   */ "FsWriteCap",
  /* 17 g_tok_arena     */ "ArenaCap",
  /* 18 g_tok_thread    */ "ThreadCap",
  /* 19 g_tok_gpu       */ "GpuCap",
  /* 20 g_tok_compiler_read */ "CompilerReadCap",
  /* 21 g_tok_metrics   */ "MetricsCap",
  /* 22 g_tok_alloc     */ "AllocCap",
  /* 23 g_tok_time      */ "TimeCap",
  /* 24 g_tok_rand      */ "RandCap",
  /* 25 g_tok_ffi       */ "FfiCap",
};

/* Lazy-populated rights-mask table, indexed by substrate cap index.
 * Populated on first oo_cap_check_with_ocap call under pthread_once.
 * The substrate → language-token mapping is in SUBSTRATE_TO_LANGUAGE;
 * the rights mask comes from the OCap record. */
static long long g_ocap_rights[26];
static pthread_once_t g_ocap_once = PTHREAD_ONCE_INIT;

/* Phase 2 test-only hook: when > 0, the next oo_cap_check_with_ocap
 * call returns 0 and clears the flag. Used by the challenger probe
 * to force the dual-check wrapper to see OCap disagreement. The
 * flag is volatile + simple int (not atomic) because it's only set
 * by the test process before a forked child runs — no concurrent
 * access in production. */
static volatile int g_test_force_fail = 0;

static void ocap_init_once(void) {
  /* For each substrate cap, look up the language token name, then
   * get the rights mask from the OCap record. If the lookup misses
   * (record returns empty name), the rights mask is 0 — fail-closed. */
  OoSList names = ocap_to_oodar_all_names();
  for (int i = 0; i < 26; i++) {
    const char *lang = SUBSTRATE_TO_LANGUAGE[i];
    OoStr name;
    name.data = (char *)lang;
    name.len = (long long)strlen(lang);
    long long mask = ocap_to_oodar_rights_for_name(name);
    g_ocap_rights[i] = mask;
  }
  oo_slist_release(names);
}

/* The substrate-cap → index lookup. We avoid a 26-entry token-to-index
 * map by using the index from oo_cap_self_token ordering, but we still
 * need to translate "given a cap, which substrate index is it?" since
 * callers pass tokens, not indices. */
static int find_substrate_index(long long cap) {
  /* Linear scan through all 26 tokens. This runs once per cap check,
   * but most programs use a small set of caps (4-8 in practice), so
   * the constant factor is small. Future optimization: cache the
   * last-found index (most callers check the same cap repeatedly). */
  for (int i = 0; i < 26; i++) {
    if (oo_cap_self_token(i) == cap) return i;
  }
  return -1;
}

/* Public C ABI: oo_cap_check_with_ocap(cap, required_rights) -> int
 *
 * Returns 1 iff:
 *   1. cap is non-zero (zero is fail-closed on absence).
 *   2. cap matches one of the 26 substrate tokens (real cap, not
 *      a forged value).
 *   3. The OCap rights mask for the corresponding language token
 *      contains all the required bits (subset rule).
 *
 * Returns 0 otherwise. Does NOT exit(1) — this is a fail-soft check;
 * the existing oo_cap_require_* gates do the exit if needed. */
int oo_cap_check_with_ocap(long long cap, long long required_rights) {
  OO_ENTRY();
  if (g_test_force_fail) {
    g_test_force_fail = 0;
    return 0;
  }
  if (cap == 0) return 0;
  pthread_once(&g_ocap_once, ocap_init_once);
  int idx = find_substrate_index(cap);
  if (idx < 0) return 0;  /* not a real token — forge attempt */
  long long granted = g_ocap_rights[idx];
  /* Bitwise subset check: required bits must all be set in granted. */
  return (granted & required_rights) == required_rights;
}

void oo_cap_bridge_set_test_force_fail(int on) {
  g_test_force_fail = on ? 1 : 0;
}

/* Diagnostic accessor for the challenger probe. Returns the rights
 * mask for the substrate cap at index `which` (0..25), or -1 if
 * the index is out of range. Used by tests_challenger_ocap_bridge.c
 * to verify the bridge's mapping table matches the documented
 * expectations. */
long long oo_cap_ocap_rights_at(int which) {
  if (which < 0 || which >= 26) return -1LL;
  pthread_once(&g_ocap_once, ocap_init_once);
  return g_ocap_rights[which];
}
