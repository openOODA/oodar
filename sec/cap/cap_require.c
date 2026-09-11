/* oo_cap_require_* — per-token cap checkers. Each function compares the
 * caller-supplied token against the process-local g_tok_* value and
 * exits on mismatch (fail-closed). Ordering: caps.c (orchestrator)
 * must be included before this file so g_tok_* and oo_caps_init are
 * visible.
 *
 * Phase 3 of the std/sec/capability bridge (v4.5.0): all 22
 * oo_cap_require_* gates are dual-check — they run the bitmask
 * check AND the OCap rights check via the dual_check helper below.
 * Disagreement aborts with exit(2) + a loud diagnostic; the
 * bitmask-fail path keeps the v3.x exit(1) + blackbox_trap_cap
 * behavior. */

#include "../../core/blackbox/blackbox.h"
#include "cap_ocap_bridge.h"

int oo_cap_is_arena(long long got) { oo_caps_init(); return got == g_tok_arena; }

/* Generic oo_cap_require: legacy bitmask-only entry point used by
 * callers that don't have an OCap-aware language token (e.g.,
 * internal cap arithmetic, the blackbox test framework). New code
 * should call the per-cap oo_cap_require_<name> wrappers below. */
void oo_cap_require(long long got, long long want, const char *op) {
  oo_caps_init();
  if (got == 0 || got != want) {
    blackbox_trap_cap(op ? op : "unknown", __func__, __FILE__, __LINE__);
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "?");
    exit(1);
  }
}

/* Phase 3 dual-check helper. All 22 oo_cap_require_* gates funnel
 * through here. `want` is the primary substrate token; `alt` is
 * the alternate if the gate accepts two substrate tokens
 * (tcp/udp/bind alias net, fsread/fswrite alias fs, process
 * alias sys). Pass alt=0 for direct (single-token) gates.
 *
 * Bitmask check: got != 0 AND (got == want OR got == alt).
 * OCap check: oo_cap_check_with_ocap(got, required_rights) — the
 * bridge's linear scan of oo_cap_self_token(0..25) finds the
 * matching substrate cap index, looks up the rights mask for the
 * corresponding NORTHSTAR language token, and asserts the subset
 * rule. Both must pass; bitmask-pass + OCap-fail aborts with
 * exit(2). */
static void dual_check(long long got, long long want, long long alt,
                       const char *op, const char *name,
                       long long required_rights) {
  oo_caps_init();
  if (got == 0 || (got != want && got != alt)) {
    blackbox_trap_cap(op ? op : name, __func__, __FILE__, __LINE__);
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n",
            op ? op : name);
    exit(1);
  }
  if (!oo_cap_check_with_ocap(got, required_rights)) {
    fprintf(stderr,
            "ERR\tcap-ocap\tdisagreement on op=%s (cap=%s): "
            "bitmask pass, ocap fail\n",
            op ? op : name, name);
    exit(2);
  }
}

void oo_cap_require_fs(long long got, const char *op) { dual_check(got, g_tok_fs, 0, op, "fs", 1); }
void oo_cap_require_sys(long long got, const char *op) { dual_check(got, g_tok_sys, 0, op, "sys", 1); }
void oo_cap_require_env(long long got, const char *op) { dual_check(got, g_tok_env, 0, op, "env", 1); }
void oo_cap_require_net(long long got, const char *op) { dual_check(got, g_tok_net, 0, op, "net", 1); }
void oo_cap_require_sign(long long got, const char *op) { dual_check(got, g_tok_sign, 0, op, "sign", 1); }
/* v2.1.0: removed oo_cap_require_sync, oo_cap_require_mem (dead caps). */
void oo_cap_require_audio(long long got, const char *op) { dual_check(got, g_tok_audio, 0, op, "audio", 1); }
void oo_cap_require_camera(long long got, const char *op) { dual_check(got, g_tok_camera, 0, op, "camera", 1); }
void oo_cap_require_usb(long long got, const char *op) { dual_check(got, g_tok_usb, 0, op, "usb", 1); }
void oo_cap_require_hid(long long got, const char *op) { dual_check(got, g_tok_hid, 0, op, "hid", 1); }
void oo_cap_require_window(long long got, const char *op) { dual_check(got, g_tok_window, 0, op, "window", 1); }
void oo_cap_require_frame(long long got, const char *op) { dual_check(got, g_tok_frame, 0, op, "frame", 1); }
void oo_cap_require_arena(long long got, const char *op) { dual_check(got, g_tok_arena, 0, op, "arena", 1); }
void oo_cap_require_thread(long long got, const char *op) { dual_check(got, g_tok_thread, 0, op, "thread", 1); }
void oo_cap_require_gpu(long long got, const char *op) { dual_check(got, g_tok_gpu, 0, op, "gpu", 1); }
void oo_cap_require_compiler_read(long long got, const char *op) { dual_check(got, g_tok_compiler_read, 0, op, "compiler_read", 1); }
void oo_cap_require_metrics(long long got, const char *op) { dual_check(got, g_tok_metrics, 0, op, "metrics", 1); }

/* v2.1.0: removed oo_cap_require_http (dead cap). */
void oo_cap_require_tcp(long long got, const char *op) { dual_check(got, g_tok_tcp, g_tok_net, op, "tcp", 1); }
void oo_cap_require_udp(long long got, const char *op) { dual_check(got, g_tok_udp, g_tok_net, op, "udp", 1); }
void oo_cap_require_bind(long long got, const char *op) { dual_check(got, g_tok_bind, g_tok_net, op, "bind", 1); }
void oo_cap_require_fsread(long long got, const char *op) { dual_check(got, g_tok_fsread, g_tok_fs, op, "fsread", 1); }
void oo_cap_require_fswrite(long long got, const char *op) { dual_check(got, g_tok_fswrite, g_tok_fs, op, "fswrite", 1); }
void oo_cap_require_process(long long got, const char *op) { dual_check(got, g_tok_process, g_tok_sys, op, "process", 1); }
