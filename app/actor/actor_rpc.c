/* v2.3.0 split: cap-rpc (sign-style HMAC over payload). Folded out of
 * actor.c. v2.1.0 changed gating from ThreadCap to SignCap: cap-rpc is a
 * sign-style operation (HMAC over the payload), not a thread-spawn
 * operation. ThreadCap was too coarse — every actor recipient would have
 * needed ThreadCap just to verify a signed message.
 *
 * v2.2.0: this TU is the ONLY place in app/ that pulls in the private
 * crypto primitives header. The dependency is bounded to two functions
 * and both are the cap_rpc HMAC path (oo_rpc_mac + the constant-time
 * compare in oo_cap_rpc_recv):
 *
 *   crypto_hmac_sha256_internal(key, msg)   — oo_rpc_mac() below
 *   crypto_ct_cmp(a, b, n)                  — oo_cap_rpc_recv() below
 *
 * No other crypto_*_internal symbol is used here, and the include is
 * not transitive (nothing in app/actor that depends on us re-exports
 * it). The intent is documented so a future maintainer can find the
 * use-site; a future Floor break (v3.0.0+) should expose a cap-gated
 * public HMAC primitive in oodar.h and drop this private include.
 *
 * NOTE: oodar.h also pulls in crypto_internal.h when OODAR_CRYPTO_INTERNAL
 * is defined, but this TU does NOT use that guard — the dependency is
 * unconditional, intentional, and scoped to the cap_rpc HMAC. */
#include "../../oodar.h"
#include "../../sec/crypto/crypto_internal.h"
#include <stdint.h>

static OoStr oo_rpc_mac(long long cap, OoStr payload) {
  char key[32];
  snprintf(key, sizeof key, "%llx", (unsigned long long)cap);
  return crypto_hmac_sha256_internal(oo_str_lit(key), payload);
}

OoResS oo_cap_rpc_send(long long cap, OoStr payload) {
  OoResS r;
  OoStr mac;
  char *out;
  /* v2.1.0: was oo_cap_require_thread. Cap-rpc is a sign-style operation
   * (HMAC over the payload), not a thread-spawn operation. ThreadCap is
   * too coarse — every actor recipient would have needed ThreadCap just
   * to verify a signed message. SignCap is the right cap. */
  oo_cap_require_sign(cap, "cap_rpc_send");
  r.ok = 0; r.val = oo_str_lit("cap_rpc_send: bad payload");
  if (payload.len < 0 || payload.len > 192) return r;
  mac = oo_rpc_mac(cap, payload);
  if (!mac.data || mac.len != 64) {
    if (mac.data) oo_str_release(mac);
    return r;
  }
  out = oo_str_alloc_payload((size_t)(64 + payload.len));
  memcpy(out, mac.data, 64);
  oo_str_release(mac);
  if (payload.len > 0 && payload.data)
    memcpy(out + 64, payload.data, (size_t)payload.len);
  r.ok = 1; r.val.data = out; r.val.len = 64 + payload.len;
  return r;
}

OoResS oo_cap_rpc_recv(long long cap, OoStr sealed) {
  OoResS r;
  OoStr pay, mac;
  char *out;
  /* v2.1.0: see cap_rpc_send — SignCap, not ThreadCap. */
  oo_cap_require_sign(cap, "cap_rpc_recv");
  r.ok = 0; r.val = oo_str_lit("cap_rpc_recv: hmac");
  if (!sealed.data || sealed.len < 64) return r;
  pay.data = sealed.data + 64; pay.len = sealed.len - 64;
  mac = oo_rpc_mac(cap, pay);
  if (mac.len != 64 || crypto_ct_cmp(mac.data, sealed.data, 64) != 0) {
    if (mac.data) oo_str_release(mac);
    return r;
  }
  oo_str_release(mac);
  out = oo_str_alloc_payload((size_t)pay.len);
  if (pay.len > 0) memcpy(out, pay.data, (size_t)pay.len);
  r.ok = 1; r.val.data = out; r.val.len = pay.len;
  return r;
}
