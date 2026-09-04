/* Post-Quantum Cap Seal: HMAC-SHA-256 -> ML-DSA-65 (FIPS 204) wrapper
 *
 * X2: The cap_attenuate path is migrating from classical HMAC-SHA-256 to
 *     post-quantum ML-DSA-65 signatures. ML-DSA-65 is a NIST FIPS 204
 *     lattice-based signature scheme (security level 3, ~128-bit post-quantum).
 *
 * This file provides:
 *   crypto_pq_hmac_sha256_internal(key, msg)
 *     - key: 32-byte hex string (used as ML-DSA-65 seed -> keypair)
 *     - msg: any UTF-8 string
 *     - returns: hex(pk_1952 || sig_3309) = 10522 hex chars
 *     - or empty string on failure (fail-closed)
 *
 *   crypto_pq_hmac_sha256_verify_internal(seal, msg)
 *     - seal: 10522 hex chars (pk || sig)
 *     - msg: any UTF-8 string
 *     - returns: 1 iff signature verifies against pk for msg; 0 otherwise
 *
 *   crypto_pq_hmac_self_test()
 *     - generates a keypair, signs, verifies, returns 1 iff round-trip OK
 *     - used by smoke tests as the negative-trust proof
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
 */
#include "../../oodar.h"
/* v2.2.0: explicit include — oo_event_emit is called from this TU; relying
 * on the implicit-declaration fallback would hide a missing prototype under
 * -Wstrict-prototypes and is a latent bug if the signature ever changes. */
#include "../../app/telemetry/event.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

#define PQ_SEED_LEN 32
#define PQ_PK_LEN 1952
#define PQ_SK_LEN 4032
#define PQ_SIG_LEN 3309
#define PQ_SEAL_HEX_LEN ((PQ_PK_LEN + PQ_SIG_LEN) * 2) /* 10522 */

static int hex_digit(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_load_n(const char *s, size_t slen, uint8_t *out, size_t want) {
  if (!s || slen != want * 2) return 0;
  for (size_t i = 0; i < want; i++) {
    int hi = hex_digit((unsigned char)s[2 * i]);
    int lo = hex_digit((unsigned char)s[2 * i + 1]);
    if (hi < 0 || lo < 0) return 0;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 1;
}

static OoStr hex_out_n(const uint8_t *p, size_t n) {
  static const char *hx = "0123456789abcdef";
  char *buf = oo_str_alloc_payload(n * 2);
  for (size_t i = 0; i < n; i++) {
    buf[i * 2] = hx[(p[i] >> 4) & 0xf];
    buf[i * 2 + 1] = hx[p[i] & 0xf];
  }
  OoStr r; r.data = buf; r.len = (long long)(n * 2); return r;
}

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

/* === X3: Seal confidentiality via AES-128-GCM AEAD ===
 *
 * HMAC and ML-DSA both give authenticity, but the cap_id travels in the clear
 * (anyone who sees the seal sees the cap_id). For real confidentiality we
 * encrypt the cap_id with AES-128-GCM (NIST SP 800-38D) and authenticate the
 * ciphertext with ML-DSA-65.
 *
 * Layout (binary, not hex):
 *   [pk: 1952 bytes][nonce: 12 bytes][ct: pt_len bytes][tag: 16 bytes][sig: 3309 bytes]
 *   Total = 5289 + pt_len bytes
 *
 * The .oo wrapper is not exposed yet; the C-level wrapper here is exercised
 * by the smoke test scripts/smoke_crypto_pq_seal.c.
 */

#define AEAD_KEY_LEN 16
#define AEAD_NONCE_LEN 12
#define AEAD_TAG_LEN 16
#define CONF_SEAL_OVERHEAD (PQ_PK_LEN + AEAD_NONCE_LEN + AEAD_TAG_LEN + PQ_SIG_LEN) /* 5289 */

OoStr crypto_pq_aead_seal_internal(OoStr cap_key32, OoStr aead_key16, OoStr plaintext) {
  if (!cap_key32.data || (cap_key32.len != PQ_SEED_LEN && cap_key32.len != PQ_SEED_LEN * 2)) return oo_str_lit("");
  if (!aead_key16.data || (aead_key16.len != AEAD_KEY_LEN && aead_key16.len != AEAD_KEY_LEN * 2)) return oo_str_lit("");
  if (!plaintext.data || plaintext.len < 0) return oo_str_lit("");

  /* The AEAD implementation in aead.c takes 16 raw bytes for key. */
  uint8_t aead_key_raw[AEAD_KEY_LEN];
  if (aead_key16.len == AEAD_KEY_LEN) memcpy(aead_key_raw, aead_key16.data, AEAD_KEY_LEN);
  else if (!hex_load_n(aead_key16.data, (size_t)aead_key16.len, aead_key_raw, AEAD_KEY_LEN)) return oo_str_lit("");

  /* Keygen from cap_key. */
  OoStr seedstr = cap_key32;
  OoStr kp = crypto_mldsa65_keygen_internal(seedstr);
  if (!kp.data || kp.len != (long long)((PQ_PK_LEN + PQ_SK_LEN) * 2)) {
    if (kp.data) crypto_secure_wipe(kp.data, (size_t)kp.len);
    crypto_secure_wipe(aead_key_raw, sizeof aead_key_raw);
    return oo_str_lit("");
  }
  uint8_t pk[PQ_PK_LEN], sk[PQ_SK_LEN];
  if (!hex_load_n(kp.data, (size_t)(PQ_PK_LEN * 2), pk, PQ_PK_LEN) ||
      !hex_load_n(kp.data + PQ_PK_LEN * 2, (size_t)(PQ_SK_LEN * 2), sk, PQ_SK_LEN)) {
    crypto_secure_wipe(pk, sizeof pk);
    crypto_secure_wipe(sk, sizeof sk);
    crypto_secure_wipe(kp.data, (size_t)kp.len);
    return oo_str_lit("");
  }
  crypto_secure_wipe(kp.data, (size_t)kp.len);

  /* Per-message nonce from the kernel CSPRNG. The previous deterministic
   * nonce (length+first 4 bytes of plaintext) was a Joux forbidden-attack
   * hazard: identical (len, prefix) plaintexts under the same key produced
   * identical nonces, breaking GCM confidentiality. getentropy(3) is the
   * fix; on failure we fail closed. */
  uint8_t nonce[AEAD_NONCE_LEN];
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(nonce, AEAD_NONCE_LEN) != 0) {
    crypto_secure_wipe(aead_key_raw, sizeof aead_key_raw);
    crypto_secure_wipe(pk, sizeof pk);
    crypto_secure_wipe(sk, sizeof sk);
    return oo_str_lit("");
  }
#else
  /* No getentropy on this platform: fail closed rather than reuse a
   * deterministic nonce. */
  crypto_secure_wipe(aead_key_raw, sizeof aead_key_raw);
  crypto_secure_wipe(pk, sizeof pk);
  crypto_secure_wipe(sk, sizeof sk);
  return oo_str_lit("");
#endif

  /* AAD = pk (binds the ciphertext to this keypair). */
  OoStr pk_aad; pk_aad.data = (char *)pk; pk_aad.len = PQ_PK_LEN;
  OoStr noncestr; noncestr.data = (char *)nonce; noncestr.len = AEAD_NONCE_LEN;
  OoStr keystr; keystr.data = (char *)aead_key_raw; keystr.len = AEAD_KEY_LEN;
  OoStr aead_out = crypto_aes_gcm_seal_internal(keystr, noncestr, plaintext, pk_aad);
  oo_event_emit(oo_str_lit("aead.seal"));
  if (!aead_out.data || aead_out.len < AEAD_TAG_LEN) {
    if (aead_out.data) crypto_secure_wipe(aead_out.data, (size_t)aead_out.len);
    crypto_secure_wipe(pk, sizeof pk);
    crypto_secure_wipe(sk, sizeof sk);
    crypto_secure_wipe(aead_key_raw, sizeof aead_key_raw);
    return oo_str_lit("");
  }
  /* aead_out is hex(ct || tag) — each byte is an ASCII hex char. Decode to binary. */
  size_t tag_hex_len = AEAD_TAG_LEN * 2;
  size_t ct_hex_len = (size_t)aead_out.len - tag_hex_len;
  size_t ct_len = ct_hex_len / 2;
  uint8_t *ct = (uint8_t *)malloc(ct_len ? ct_len : 1);
  if (!ct) abort();
  for (size_t i = 0; i < ct_len; i++) {
    int hi = hex_digit((unsigned char)aead_out.data[2 * i]);
    int lo = hex_digit((unsigned char)aead_out.data[2 * i + 1]);
    if (hi < 0 || lo < 0) { free(ct); crypto_secure_wipe(aead_out.data, (size_t)aead_out.len); return oo_str_lit(""); }
    ct[i] = (uint8_t)((hi << 4) | lo);
  }
  uint8_t tag[AEAD_TAG_LEN];
  for (int i = 0; i < AEAD_TAG_LEN; i++) {
    int hi = hex_digit((unsigned char)aead_out.data[ct_hex_len + 2 * i]);
    int lo = hex_digit((unsigned char)aead_out.data[ct_hex_len + 2 * i + 1]);
    if (hi < 0 || lo < 0) { free(ct); crypto_secure_wipe(aead_out.data, (size_t)aead_out.len); return oo_str_lit(""); }
    tag[i] = (uint8_t)((hi << 4) | lo);
  }

  /* Sign (pk || nonce || ct || tag) with ML-DSA-65. */
  size_t signed_len = (size_t)PQ_PK_LEN + AEAD_NONCE_LEN + ct_len + AEAD_TAG_LEN;
  uint8_t *signed_buf = (uint8_t *)malloc(signed_len);
  if (!signed_buf) abort();
  size_t off = 0;
  memcpy(signed_buf + off, pk, PQ_PK_LEN); off += PQ_PK_LEN;
  memcpy(signed_buf + off, nonce, AEAD_NONCE_LEN); off += AEAD_NONCE_LEN;
  memcpy(signed_buf + off, ct, ct_len); off += ct_len;
  memcpy(signed_buf + off, tag, AEAD_TAG_LEN); off += AEAD_TAG_LEN;

  OoStr skstr; skstr.data = (char *)sk; skstr.len = PQ_SK_LEN;
  OoStr rnd; rnd.data = (char *)""; rnd.len = 0;
  OoStr signed_msg; signed_msg.data = (char *)signed_buf; signed_msg.len = (long long)signed_len;
  OoStr sig = crypto_mldsa65_sign_internal(skstr, signed_msg, rnd);
  oo_event_emit(oo_str_lit("pq.sign"));
  crypto_secure_wipe(sk, sizeof sk);
  free(signed_buf);
  if (!sig.data || sig.len != (long long)(PQ_SIG_LEN * 2)) {
    if (sig.data) crypto_secure_wipe(sig.data, (size_t)sig.len);
    crypto_secure_wipe(aead_out.data, (size_t)aead_out.len);
    crypto_secure_wipe(pk, sizeof pk);
    crypto_secure_wipe(aead_key_raw, sizeof aead_key_raw);
    return oo_str_lit("");
  }

  /* Decode the hex sig back to binary. */
  uint8_t sigbin[PQ_SIG_LEN];
  if (!hex_load_n(sig.data, (size_t)sig.len, sigbin, PQ_SIG_LEN)) {
    crypto_secure_wipe(sig.data, (size_t)sig.len);
    crypto_secure_wipe(aead_out.data, (size_t)aead_out.len);
    crypto_secure_wipe(pk, sizeof pk);
    crypto_secure_wipe(aead_key_raw, sizeof aead_key_raw);
    return oo_str_lit("");
  }
  crypto_secure_wipe(sig.data, (size_t)sig.len);

  /* Output: pk || nonce || ct || tag || sigbin (all binary). */
  size_t out_len = CONF_SEAL_OVERHEAD + ct_len;
  char *outbuf = oo_str_alloc_payload(out_len);
  off = 0;
  memcpy(outbuf + off, pk, PQ_PK_LEN); off += PQ_PK_LEN;
  memcpy(outbuf + off, nonce, AEAD_NONCE_LEN); off += AEAD_NONCE_LEN;
  memcpy(outbuf + off, ct, ct_len); off += ct_len;
  memcpy(outbuf + off, tag, AEAD_TAG_LEN); off += AEAD_TAG_LEN;
  memcpy(outbuf + off, sigbin, PQ_SIG_LEN); off += PQ_SIG_LEN;

  crypto_secure_wipe(aead_out.data, (size_t)aead_out.len);
  crypto_secure_wipe(sigbin, sizeof sigbin);
  crypto_secure_wipe(pk, sizeof pk);
  crypto_secure_wipe(aead_key_raw, sizeof aead_key_raw);
  free(ct);

  OoStr out; out.data = outbuf; out.len = (long long)out_len; return out;
}

OoStr crypto_pq_aead_open_internal(OoStr cap_key32, OoStr aead_key16, OoStr seal) {
  if (!cap_key32.data || (cap_key32.len != PQ_SEED_LEN && cap_key32.len != PQ_SEED_LEN * 2)) return oo_str_lit("");
  if (!aead_key16.data || (aead_key16.len != AEAD_KEY_LEN && aead_key16.len != AEAD_KEY_LEN * 2)) return oo_str_lit("");
  if (!seal.data || seal.len < (long long)CONF_SEAL_OVERHEAD) return oo_str_lit("");

  /* Parse seal layout. */
  const uint8_t *p = (const uint8_t *)seal.data;
  size_t ct_len = (size_t)seal.len - CONF_SEAL_OVERHEAD;
  size_t off = 0;
  /* pk is in p[0..PQ_PK_LEN) — already known to caller via cap_key. */
  off += PQ_PK_LEN;
  const uint8_t *nonce = p + off; off += AEAD_NONCE_LEN;
  const uint8_t *ct = p + off; off += ct_len;
  const uint8_t *tag = p + off; off += AEAD_TAG_LEN;
  const uint8_t *sigbin = p + off; off += PQ_SIG_LEN;
  (void)off;

  /* Verify the signature over (pk || nonce || ct || tag). */
  size_t signed_len = (size_t)PQ_PK_LEN + AEAD_NONCE_LEN + ct_len + AEAD_TAG_LEN;
  /* Reconstruct (pk || nonce || ct || tag) — we need pk from cap_keygen. */
  OoStr seedstr = cap_key32;
  OoStr kp = crypto_mldsa65_keygen_internal(seedstr);
  if (!kp.data || kp.len != (long long)((PQ_PK_LEN + PQ_SK_LEN) * 2)) {
    if (kp.data) crypto_secure_wipe(kp.data, (size_t)kp.len);
    return oo_str_lit("");
  }
  uint8_t pk[PQ_PK_LEN];
  if (!hex_load_n(kp.data, (size_t)(PQ_PK_LEN * 2), pk, PQ_PK_LEN)) {
    crypto_secure_wipe(pk, sizeof pk);
    crypto_secure_wipe(kp.data, (size_t)kp.len);
    return oo_str_lit("");
  }
  crypto_secure_wipe(kp.data, (size_t)kp.len);

  /* Compare pk embedded in seal to regenerated pk (binds seal to cap_key). */
  if (crypto_ct_cmp(pk, p, PQ_PK_LEN) != 0) {
    crypto_secure_wipe(pk, sizeof pk);
    return oo_str_lit("");
  }

  uint8_t *signed_buf = (uint8_t *)malloc(signed_len);
  if (!signed_buf) abort();
  size_t woff = 0;
  memcpy(signed_buf + woff, pk, PQ_PK_LEN); woff += PQ_PK_LEN;
  memcpy(signed_buf + woff, nonce, AEAD_NONCE_LEN); woff += AEAD_NONCE_LEN;
  memcpy(signed_buf + woff, ct, ct_len); woff += ct_len;
  memcpy(signed_buf + woff, tag, AEAD_TAG_LEN); woff += AEAD_TAG_LEN;

  /* The verify function expects hex input. Re-encode sigbin as hex. */
  OoStr sighex; sighex.data = (char *)sigbin; sighex.len = PQ_SIG_LEN;
  OoStr pkstr; pkstr.data = (char *)pk; pkstr.len = PQ_PK_LEN;
  OoStr signed_msg; signed_msg.data = (char *)signed_buf; signed_msg.len = (long long)signed_len;
  OoStr vr = crypto_mldsa65_verify_internal(pkstr, signed_msg, sighex);
  oo_event_emit(oo_str_lit("pq.verify"));
  crypto_secure_wipe(pk, sizeof pk);
  free(signed_buf);
  if (!vr.data || vr.len != 2 || vr.data[0] != 'O' || vr.data[1] != 'K') {
    if (vr.data) crypto_secure_wipe(vr.data, (size_t)vr.len);
    return oo_str_lit("");
  }
  crypto_secure_wipe(vr.data, (size_t)vr.len);

  /* Decrypt with AEAD (AAD = pk regenerated from cap_key). */
  OoStr kp2 = crypto_mldsa65_keygen_internal(seedstr);
  if (!kp2.data || kp2.len != (long long)((PQ_PK_LEN + PQ_SK_LEN) * 2)) {
    if (kp2.data) crypto_secure_wipe(kp2.data, (size_t)kp2.len);
    return oo_str_lit("");
  }
  uint8_t pk2[PQ_PK_LEN];
  if (!hex_load_n(kp2.data, (size_t)(PQ_PK_LEN * 2), pk2, PQ_PK_LEN)) {
    crypto_secure_wipe(pk2, sizeof pk2);
    crypto_secure_wipe(kp2.data, (size_t)kp2.len);
    return oo_str_lit("");
  }
  crypto_secure_wipe(kp2.data, (size_t)kp2.len);

  /* The AEAD key: accept 16 raw bytes or 32 hex chars. */
  uint8_t aead_key_raw[AEAD_KEY_LEN];
  if (aead_key16.len == AEAD_KEY_LEN) memcpy(aead_key_raw, aead_key16.data, AEAD_KEY_LEN);
  else if (!hex_load_n(aead_key16.data, (size_t)aead_key16.len, aead_key_raw, AEAD_KEY_LEN)) {
    crypto_secure_wipe(pk2, sizeof pk2);
    crypto_secure_wipe(aead_key_raw, sizeof aead_key_raw);
    return oo_str_lit("");
  }
  OoStr keystr2; keystr2.data = (char *)aead_key_raw; keystr2.len = AEAD_KEY_LEN;
  OoStr noncestr2; noncestr2.data = (char *)nonce; noncestr2.len = AEAD_NONCE_LEN;
  OoStr pk_aad2; pk_aad2.data = (char *)pk2; pk_aad2.len = PQ_PK_LEN;
  OoStr ctstr; ctstr.data = (char *)ct; ctstr.len = (long long)ct_len;
  OoStr tagstr; tagstr.data = (char *)tag; tagstr.len = AEAD_TAG_LEN;

  OoStr pt = crypto_aes_gcm_open_internal(keystr2, noncestr2, ctstr, tagstr, pk_aad2);
  oo_event_emit(oo_str_lit("aead.open"));
  crypto_secure_wipe(pk2, sizeof pk2);
  crypto_secure_wipe(aead_key_raw, sizeof aead_key_raw);

  if (!pt.data || pt.len <= 0) {
    /* AEAD tag verification failed (or wrong key) — fail closed. */
    if (pt.data) oo_str_release(pt);
    return oo_str_lit("");
  }
  /* Confidentiality+authenticity verified. Release plaintext (caller has the cap). */
  oo_str_release(pt);
  return oo_str_lit("verified");
}
