/* Post-Quantum Cap Seal — HMAC-SHA-256 / ML-DSA-65 wrapper.
 *
 * X2: The cap_attenuate path migrated from classical HMAC-SHA-256 to
 *     post-quantum ML-DSA-65 signatures. ML-DSA-65 is a NIST FIPS 204
 *     lattice-based signature scheme (security level 3, ~128-bit post-quantum).
 *
 * Public API (declared in sec/crypto/crypto_internal.h):
 *   OoStr crypto_pq_hmac_sha256_internal(OoStr key, OoStr msg);
 *   int   crypto_pq_hmac_sha256_verify_internal(OoStr seal, OoStr msg);
 *   int   crypto_pq_hmac_self_test(void);
 *
 * Returns:
 *   hmac_sha256_internal    : hex(pk_1952 || sig_3309) = 10522 hex chars, or "" on failure.
 *   hmac_sha256_verify_internal : 1 iff signature verifies, 0 otherwise.
 *   hmac_self_test          : 1 iff round-trip signs-and-verifies, 0 otherwise.
 *
 * Negative-trust contract:
 *   - The output of crypto_pq_hmac_sha256_internal is NOT 64 hex chars
 *     (that would mean we silently fell back to HMAC-SHA-256).
 *   - The verify function must succeed for a freshly-signed seal.
 *   - The verify function must fail for a tampered msg or seal.
 *
 * The output size (10522 hex) is the smoking gun: HMAC-SHA-256 returns 64 hex,
 * ML-DSA-65 returns ~10522 hex. A test that asserts output_len != 64 proves
 * the upgrade is real, not a marker.
 *
 * Hex I/O glue and size constants live in pq_sig.c (sibling).
 */
#include "../../../oodar.h"
#include <stdint.h>
#include <string.h>

/* Forward decls of ML-DSA-65 primitives from sec/pqc/mldsa/. */
OoStr crypto_mldsa65_keygen_internal(OoStr seed);
OoStr crypto_mldsa65_sign_internal(OoStr sk, OoStr msg, OoStr rnd);
OoStr crypto_mldsa65_verify_internal(OoStr pk, OoStr msg, OoStr sig);

/* External decls of hex I/O glue (pq_sig.c). */
extern int hex_digit(int c);
extern int hex_load_n(const char *s, size_t slen, uint8_t *out, size_t want);
extern OoStr hex_out_n(const uint8_t *p, size_t n);

OoStr crypto_pq_hmac_sha256_internal(OoStr key, OoStr msg) {
  if (!key.data || key.len <= 0 || !msg.data || msg.len < 0) return oo_str_lit("");

  /* ML-DSA-65 keygen from the supplied 32-byte seed (key as 64-hex).
   * If key is exactly 32 bytes raw or 64 hex chars, we use it; otherwise
   * fail-closed (return "").  cap_attenuate callers today pass OoStr with
   * 32 raw bytes; we accept both forms. */
  uint8_t seed[PQ_SEED_LEN];
  int seed_ok = 0;
  if (key.len == PQ_SEED_LEN) { memcpy(seed, key.data, PQ_SEED_LEN); seed_ok = 1; }
  else if (key.len == PQ_SEED_LEN * 2) { seed_ok = hex_load_n(key.data, (size_t)key.len, seed, PQ_SEED_LEN); }
  if (!seed_ok) { crypto_secure_wipe(seed, sizeof seed); return oo_str_lit(""); }

  OoStr seedstr; seedstr.data = (char *)seed; seedstr.len = PQ_SEED_LEN;
  OoStr kp = crypto_mldsa65_keygen_internal(seedstr);
  crypto_secure_wipe(seed, sizeof seed);
  if (!kp.data || kp.len != (long long)((PQ_PK_LEN + PQ_SK_LEN) * 2)) {
    if (kp.data) crypto_secure_wipe(kp.data, (size_t)kp.len);
    return oo_str_lit("");
  }

  /* Split kp into pk (first 1952 bytes) and sk (next 4032 bytes). */
  uint8_t pk[PQ_PK_LEN], sk[PQ_SK_LEN];
  if (!hex_load_n(kp.data, (size_t)(PQ_PK_LEN * 2), pk, PQ_PK_LEN) ||
      !hex_load_n(kp.data + PQ_PK_LEN * 2, (size_t)(PQ_SK_LEN * 2), sk, PQ_SK_LEN)) {
    crypto_secure_wipe(pk, sizeof pk);
    crypto_secure_wipe(sk, sizeof sk);
    crypto_secure_wipe(kp.data, (size_t)kp.len);
    return oo_str_lit("");
  }
  crypto_secure_wipe(kp.data, (size_t)kp.len);

  OoStr skstr; skstr.data = (char *)sk; skstr.len = PQ_SK_LEN;
  OoStr rnd; rnd.data = (char *)""; rnd.len = 0; /* deterministic sign */
  OoStr sig = crypto_mldsa65_sign_internal(skstr, msg, rnd);
  crypto_secure_wipe(sk, sizeof sk);
  if (!sig.data || sig.len != (long long)(PQ_SIG_LEN * 2)) {
    if (sig.data) crypto_secure_wipe(sig.data, (size_t)sig.len);
    crypto_secure_wipe(pk, sizeof pk);
    return oo_str_lit("");
  }

  /* Concatenate pk hex + sig hex into the seal. */
  OoStr pkhex = hex_out_n(pk, PQ_PK_LEN);
  crypto_secure_wipe(pk, sizeof pk);

  size_t seal_len = (size_t)pkhex.len + (size_t)sig.len;
  char *sealbuf = oo_str_alloc_payload(seal_len);
  memcpy(sealbuf, pkhex.data, (size_t)pkhex.len);
  memcpy(sealbuf + pkhex.len, sig.data, (size_t)sig.len);
  crypto_secure_wipe(pkhex.data, (size_t)pkhex.len);
  crypto_secure_wipe(sig.data, (size_t)sig.len);

  OoStr out; out.data = sealbuf; out.len = (long long)seal_len; return out;
}

int crypto_pq_hmac_sha256_verify_internal(OoStr seal, OoStr msg) {
  if (!seal.data || seal.len != PQ_SEAL_HEX_LEN) return 0;
  if (!msg.data || msg.len < 0) return 0;

  uint8_t pk[PQ_PK_LEN], sig[PQ_SIG_LEN];
  if (!hex_load_n(seal.data, (size_t)(PQ_PK_LEN * 2), pk, PQ_PK_LEN) ||
      !hex_load_n(seal.data + PQ_PK_LEN * 2, (size_t)(PQ_SIG_LEN * 2), sig, PQ_SIG_LEN)) {
    crypto_secure_wipe(pk, sizeof pk);
    crypto_secure_wipe(sig, sizeof sig);
    return 0;
  }

  OoStr pkstr; pkstr.data = (char *)pk; pkstr.len = PQ_PK_LEN;
  OoStr sigstr; sigstr.data = (char *)sig; sigstr.len = PQ_SIG_LEN;

  OoStr vr = crypto_mldsa65_verify_internal(pkstr, msg, sigstr);
  int rc = (vr.data && vr.len == 2 && vr.data[0] == 'O' && vr.data[1] == 'K') ? 1 : 0;
  if (vr.data) crypto_secure_wipe(vr.data, (size_t)vr.len);
  crypto_secure_wipe(pk, sizeof pk);
  crypto_secure_wipe(sig, sizeof sig);
  return rc;
}

int crypto_pq_hmac_self_test(void) {
  /* Generate a deterministic seed, sign, verify, return 1 iff round-trip OK. */
  uint8_t seed[PQ_SEED_LEN];
  for (int i = 0; i < PQ_SEED_LEN; i++) seed[i] = (uint8_t)(0x42 ^ i);
  OoStr seedstr; seedstr.data = (char *)seed; seedstr.len = PQ_SEED_LEN;

  OoStr kp = crypto_mldsa65_keygen_internal(seedstr);
  crypto_secure_wipe(seed, sizeof seed);
  if (!kp.data || kp.len != (long long)((PQ_PK_LEN + PQ_SK_LEN) * 2)) {
    if (kp.data) crypto_secure_wipe(kp.data, (size_t)kp.len);
    return 0;
  }
  uint8_t pk[PQ_PK_LEN], sk[PQ_SK_LEN];
  int ok = hex_load_n(kp.data, (size_t)(PQ_PK_LEN * 2), pk, PQ_PK_LEN) &&
           hex_load_n(kp.data + PQ_PK_LEN * 2, (size_t)(PQ_SK_LEN * 2), sk, PQ_SK_LEN);
  crypto_secure_wipe(kp.data, (size_t)kp.len);
  if (!ok) {
    crypto_secure_wipe(pk, sizeof pk);
    crypto_secure_wipe(sk, sizeof sk);
    return 0;
  }

  OoStr skstr; skstr.data = (char *)sk; skstr.len = PQ_SK_LEN;
  OoStr msg = oo_str_lit("self_test_message");
  OoStr rnd; rnd.data = (char *)""; rnd.len = 0;
  OoStr sig = crypto_mldsa65_sign_internal(skstr, msg, rnd);
  crypto_secure_wipe(sk, sizeof sk);
  if (!sig.data || sig.len != (long long)(PQ_SIG_LEN * 2)) {
    if (sig.data) crypto_secure_wipe(sig.data, (size_t)sig.len);
    crypto_secure_wipe(pk, sizeof pk);
    return 0;
  }
  OoStr pkstr; pkstr.data = (char *)pk; pkstr.len = PQ_PK_LEN;
  OoStr vr = crypto_mldsa65_verify_internal(pkstr, msg, sig);
  int rc = (vr.data && vr.len == 2 && vr.data[0] == 'O' && vr.data[1] == 'K') ? 1 : 0;
  if (vr.data) crypto_secure_wipe(vr.data, (size_t)vr.len);
  crypto_secure_wipe(sig.data, (size_t)sig.len);
  crypto_secure_wipe(pk, sizeof pk);
  return rc;
}
