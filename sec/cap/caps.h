#ifndef OODAR_CAPS_H
#define OODAR_CAPS_H
#include "../../types.h"
#include "../landlock/sandbox.h"

#define OODAR_CAP_NET 1u
#define OODAR_CAP_PROCESS 2u
#define OODAR_CAP_FSWRITE 4u
#define OODAR_CAP_FSREAD 8u
#define OODAR_CAP_SYS 16u
#define OODAR_CAP_FS 32u
#define OODAR_CAP_TIME 64u
#define OODAR_CAP_RAND 128u
#define OODAR_CAP_ALLOC 256u
#define OODAR_CAP_ARENA 512u
#define OODAR_CAP_FFI 1024u
/* v3.0.0: re-introduced OODAR_CAP_METRICS at 0x800 (the v2.1.0 AUDIT
 * bit position). The metrics counter is process-global state — a side
 * channel via counter export — so v3.0.0 gives it its own cap token.
 * The bit was reserved since v2.1.0 for exactly this kind of future
 * re-introduction; we use it now per RULES.oot §1.21 Floor break. */
#define OODAR_CAP_METRICS 2048u
/* v2.1.0: removed OODAR_CAP_AUDIT (now METRICS at 0x800), OODAR_CAP_HITL
 * (0x2000), OODAR_CAP_SYNC (0x4000), OODAR_CAP_MEM (0x8000), OODAR_CAP_HTTP
 * (0x10000) — dead caps. The remaining bit positions are reserved;
 * future re-introduction must use a different bit position to avoid
 * collision with anything that may have been packed into the gaps. */
#define OODAR_CAP_SIGN 4096u
#define OODAR_CAP_TCP (1u << 17)
#define OODAR_CAP_UDP (1u << 18)
#define OODAR_CAP_BIND (1u << 19)
#define OODAR_CAP_AUDIO (1u << 20)
#define OODAR_CAP_CAMERA (1u << 21)
#define OODAR_CAP_USB (1u << 22)
#define OODAR_CAP_HID (1u << 23)
#define OODAR_CAP_WINDOW (1u << 24)
#define OODAR_CAP_FRAME (1u << 25)
#define OODAR_CAP_THREAD (1u << 26)
#define OODAR_CAP_GPU (1u << 27)
#define OODAR_CAP_ENV (1u << 28)
#define OODAR_CAP_COMPILER_READ (1u << 29)

void oodar_cap_init(void);
void oodar_cap_drop(void);
int oodar_cap_is_sandboxed(void);
int oodar_cap_apply_seccomp_filter(uint32_t allowed_caps_mask);

long long oo_cap_grant_fs(void);
long long oo_cap_grant_sys(void);
long long oo_cap_grant_env(void);
long long oo_cap_grant_net(void);
long long oo_cap_grant_time(void);
long long oo_cap_grant_rand(void);
long long oo_cap_grant_alloc(void);
long long oo_cap_grant_arena(void);
long long oo_cap_grant_ffi(void);
/* v2.1.0: removed oo_cap_grant_audit, oo_cap_grant_hitl, oo_cap_grant_sync,
 * oo_cap_grant_mem, oo_cap_grant_http — they were declared but never
 * defined (audit, hitl) or granted-but-never-required dead caps (sync,
 * mem, http). Future-state: a re-introduction requires a Floor break
 * (v3.0.0+) with both a real grant + a real require and a documented
 * purpose. */
long long oo_cap_grant_sign(void);
long long oo_cap_grant_process(void);
long long oo_cap_grant_tcp(void);
long long oo_cap_grant_udp(void);
long long oo_cap_grant_bind(void);
long long oo_cap_grant_audio(void);
long long oo_cap_grant_camera(void);
long long oo_cap_grant_usb(void);
long long oo_cap_grant_hid(void);
long long oo_cap_grant_window(void);
long long oo_cap_grant_frame(void);
long long oo_cap_grant_fsread(void);
long long oo_cap_grant_fswrite(void);
long long oo_cap_grant_thread(void);
long long oo_cap_grant_gpu(void);
long long oo_cap_grant_compiler_read(void);
long long oo_cap_grant_metrics(void);

void oo_cap_require(long long got, long long want, const char *op);
void oo_cap_require_fs(long long got, const char *op);
void oo_cap_require_sys(long long got, const char *op);
void oo_cap_require_env(long long got, const char *op);
void oo_cap_require_net(long long got, const char *op);
void oo_cap_require_time(long long got, const char *op);
void oo_cap_require_rand(long long got, const char *op);
void oo_cap_require_alloc(long long got, const char *op);
void oo_cap_require_arena(long long got, const char *op);
int oo_cap_is_arena(long long got);
int oo_cap_is_alloc(long long got);
void oo_cap_require_ffi(long long got, const char *op);
/* v2.1.0: removed oo_cap_require_audit, oo_cap_require_hitl (declared but
 * never defined), oo_cap_require_sync/mem/http (dead). */
void oo_cap_require_sign(long long got, const char *op);
void oo_cap_require_process(long long got, const char *op);
void oo_cap_require_tcp(long long got, const char *op);
void oo_cap_require_udp(long long got, const char *op);
void oo_cap_require_bind(long long got, const char *op);
void oo_cap_require_audio(long long got, const char *op);
void oo_cap_require_camera(long long got, const char *op);
void oo_cap_require_usb(long long got, const char *op);
void oo_cap_require_hid(long long got, const char *op);
void oo_cap_require_window(long long got, const char *op);
void oo_cap_require_frame(long long got, const char *op);
void oo_cap_require_fsread(long long got, const char *op);
void oo_cap_require_fswrite(long long got, const char *op);
void oo_cap_require_thread(long long got, const char *op);
void oo_cap_require_gpu(long long got, const char *op);
void oo_cap_require_compiler_read(long long got, const char *op);
void oo_cap_require_metrics(long long got, const char *op);

/* v2.1.0: cap_attenuate and cap_attenuate_ok (no oo_ prefix) are gone.
 * They were declared but never defined; the canonical entry points are
 * oo_cap_attenuate / oo_cap_attenuate_ok. */
OoStr oo_cap_attenuate(OoStr parent_hmac, OoStr child_rights);
int oo_cap_attenuate_ok(OoStr parent_hmac, OoStr child_rights);
OoStr oo_cap_kernel_seal(long long sys, OoStr cap_id);
OoStr oo_enclave_enter(long long sys, OoStr sealed);

/* v2.2.0 item #22: path-scoped FsReadCap attenuator (NORTHSTAR §4.2).
 * A bare FsReadCap grants read access to ANY path. An OoPathCap is an
 * attenuation bound to a specific absolute path prefix. The MAC is the
 * HMAC-SHA-256 of (parent_cap || prefix) under the kernel's per-process
 * HMAC key (g_kernel_hmac_key), so a forged prefix or parent_cap fails
 * the constant-time check in oo_path_cap_check.
 *
 * Chain rule: the cap parameter to oo_attenuate_fsread_to_path may be
 * either the raw FsReadCap/FS token OR the parent_cap field of a
 * previously-derived OoPathCap — re-attenuation is allowed and reuses
 * the same MAC key, so each prefix gets a distinct, non-spoofable MAC.
 *
 * Ownership: OoPathCap holds a borrow of the caller's prefix OoStr
 * (shallow copy of the (data, len) view). The caller MUST keep the
 * underlying prefix buffer alive for as long as the OoPathCap is used.
 */
typedef struct {
  long long parent_cap;   /* the cap this is attenuated from (FsReadCap / FsCap / prior OoPathCap.parent_cap) */
  OoStr prefix;           /* absolute path prefix this cap is allowed to read (caller-owned) */
  unsigned char mac[32];  /* HMAC-SHA-256(g_kernel_hmac_key, parent_cap || prefix) */
} OoPathCap;

OoPathCap oo_attenuate_fsread_to_path(long long cap, OoStr prefix);
int oo_path_cap_check(OoPathCap path_cap, OoStr path);

/* v3.2.2: diagnostic API for qa/tests_challenger_differential_cap.c.
 * Returns the cap token at index 0..21, or 0 if out of range. The
 * 22 tokens exposed are the canonical store at sec/cap/caps.c; the
 * other 4 (g_tok_time, g_tok_rand, g_tok_alloc, g_tok_arena,
 * g_tok_ffi, g_tok_metrics) live in their respective files. The
 * differential test forks N children, reads g_tok_fs (index 0) from
 * each, and verifies all N are unique. An LCG fallback for
 * getentropy() failure (the round-4 CRITICAL) would produce the
 * same token across all children and fail the test. */
long long oo_cap_self_token(int which);

#endif
