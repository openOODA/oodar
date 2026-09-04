/* Post-Quantum Cap Seal — Seal side (encrypt + sign).
 * Sibling: pq_aead_open.c (verify + decrypt). Orchestrator: pq_aead.c
 * (the public API declarations). HMAC and ML-DSA both give authenticity,
 * but the cap_id travels in the clear. For real confidentiality we
 * encrypt the cap_id with AES-128-GCM (NIST SP 800-38D) and
 * authenticate the ciphertext with ML-DSA-65.
 *
 * Layout (binary, not hex):
 *   [pk: 1952 bytes][nonce: 12 bytes][ct: pt_len bytes][tag: 16 bytes][sig: 3309 bytes]
 *   Total = 5289 + pt_len bytes
 *
 * The .oo wrapper is not exposed yet; the C-level wrapper here is
 * exercised by the smoke test scripts/smoke_crypto_pq_seal.c. */
#include "../../../oodar.h"
#include "../../../core/event/event.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

/* Forward decls of ML-DSA-65 primitives from sec/pqc/mldsa/. */
OoStr crypto_mldsa65_keygen_internal(OoStr seed);
OoStr crypto_mldsa65_sign_internal(OoStr sk, OoStr msg, OoStr rnd);

/* Forward decls of AES-GCM primitives from sec/crypto/aead.c. */
OoStr crypto_aes_gcm_seal_internal(OoStr key, OoStr nonce, OoStr pt, OoStr aad);

/* External decls of hex I/O glue (pq_sig.c). */
extern int hex_digit(int c);
extern int hex_load_n(const char *s, size_t slen, uint8_t *out, size_t want);

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
   * hazard: identical (len,prefix) plaintexts under the same key produced
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
