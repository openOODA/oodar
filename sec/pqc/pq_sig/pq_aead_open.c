/* Post-Quantum Cap Seal — Open side (verify + decrypt).
 * Sibling: pq_aead_seal.c (encrypt + sign). Orchestrator: pq_aead.c
 * (the public API declarations). Decodes the seal layout
 *   [pk: 1952 bytes][nonce: 12 bytes][ct: pt_len bytes][tag: 16 bytes][sig: 3309 bytes]
 * regenerates pk from cap_key, binds it via ct_cmp, verifies the
 * ML-DSA-65 signature over (pk || nonce || ct || tag), and decrypts
 * with AES-128-GCM (AAD = regenerated pk). Fail-closed on every
 * verification miss. */
#include "../../../oodar.h"
#include "../../../app/telemetry/event.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Forward decls of ML-DSA-65 primitives from sec/pqc/mldsa/. */
OoStr crypto_mldsa65_keygen_internal(OoStr seed);
OoStr crypto_mldsa65_verify_internal(OoStr pk, OoStr msg, OoStr sig);

/* Forward decls of AES-GCM primitives from sec/crypto/aead.c. */
OoStr crypto_aes_gcm_open_internal(OoStr key, OoStr nonce, OoStr ct, OoStr tag, OoStr aad);

/* External decls of hex I/O glue (pq_sig.c). */
extern int hex_load_n(const char *s, size_t slen, uint8_t *out, size_t want);

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
