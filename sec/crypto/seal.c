/* v2.2.0: public cap-gated AEAD wrappers (oo_seal / oo_open).
 *
 * The AES-GCM seal/open primitives themselves are private
 * (crypto_aes_gcm_seal_internal / crypto_aes_gcm_open_internal, declared
 * in crypto_internal.h and visible only to .c files in the umbrella).
 * This file provides the public cap-gated surface that oodac-emitted
 * code calls. The cap required is SignCap (AEAD is a sign-style
 * symmetric operation; same cap as oo_cg_sign / oo_cap_rpc_*).
 *
 * On a bad cap, the function refuses with the canonical OoResS error
 * string (never NULL, never exit(1) — caller-driven error path).
 */
#include "../../oodar.h"
#include "../crypto/crypto_internal.h"

OoResS oo_seal(long long cap, OoStr key, OoStr nonce, OoStr plaintext, OoStr aad) {
  OoResS r;
  oo_cap_require_sign(cap, "seal");
  r.val = crypto_aes_gcm_seal_internal(key, nonce, plaintext, aad);
  /* Internal returns empty OoStr on bad key/nonce. Surface as a tagged error. */
  if (r.val.data == NULL || r.val.len == 0) {
    r.ok = 0;
    r.val = oo_str_lit("E_AEAD");
  } else {
    r.ok = 1;
  }
  return r;
}

OoResS oo_open(long long cap, OoStr key, OoStr nonce, OoStr ct, OoStr tag, OoStr aad) {
  OoResS r;
  oo_cap_require_sign(cap, "open");
  r.val = crypto_aes_gcm_open_internal(key, nonce, ct, tag, aad);
  /* Internal returns empty OoStr on auth failure (tag mismatch) OR bad
   * key/nonce/tag length. The two are indistinguishable to the caller,
   * which is the correct AEAD contract (no oracle). */
  if (r.val.data == NULL || r.val.len == 0) {
    r.ok = 0;
    r.val = oo_str_lit("E_AEAD");
  } else {
    r.ok = 1;
  }
  return r;
}
