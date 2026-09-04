/* FIPS 203 ML-KEM-768 — KEM encaps/decaps operations.
 *
 * Public API (declared in sec/crypto/crypto_internal.h):
 *   OoStr crypto_mlkem768_encaps_internal(OoStr ek, OoStr m);
 *   OoStr crypto_mlkem768_decaps_internal(OoStr dk, OoStr ct);
 *
 * These wrap the KPKE encrypt/decrypt primitives (defined in
 * mlkem_internal.c) and re-bind them to the KEM domain (implicit
 * rejection, hex I/O). Keygen lives in mlkem.c.
 */
#include "../../../oodar.h"
#include <stdint.h>

/* Forward decls of SHA3 family used to bind the KEM randomness. */
void oo_sha3_256_bytes(const uint8_t *in, size_t n, uint8_t out[32]);
void oo_sha3_512_bytes(const uint8_t *in, size_t n, uint8_t out[64]);
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn);

/* KPKE encrypt/decrypt (mlkem_internal.c). */
void kpke_encrypt(const uint8_t pk[1184], const uint8_t m[32], const uint8_t coins[32], uint8_t c[1088]);
void kpke_decrypt(const uint8_t skc[1152], const uint8_t c[1088], uint8_t m[32]);

/* Hex I/O glue shared with mlkem.c (defined in mlkem_internal.c). */
extern int k_hex_load(OoStr s, uint8_t *out, size_t want);
extern OoStr k_hex_out(const uint8_t *p, size_t n);
extern OoStr k_hex_out_cat(const uint8_t *a, size_t na, const uint8_t *b, size_t nb);

/* ML-KEM.Encaps(ek, m): shared secret K = SHA3-512(m || H(ek)) [:32],
 * ciphertext c = KPKE.Encrypt(ek, m, K[32:]).
 * Returns hex(c || K) = (1088 + 32) * 2 = 2240 hex chars, or "" on failure. */
OoStr crypto_mlkem768_encaps_internal(OoStr ek, OoStr m) {
  uint8_t pk[1184], msg[32], kr[64], ct[1088], h[32], min[64];
  OoStr r;
  memset(msg, 0, sizeof msg); memset(kr, 0, sizeof kr); memset(min, 0, sizeof min);
  if (!k_hex_load(ek, pk, 1184)) {
    crypto_secure_wipe(msg, sizeof msg);
    return oo_str_lit("");
  }
  if (!k_hex_load(m, msg, 32)) {
    crypto_secure_wipe(msg, sizeof msg);
    return oo_str_lit("");
  }
  oo_sha3_256_bytes(pk, 1184, h);
  memcpy(min, msg, 32); memcpy(min + 32, h, 32);
  oo_sha3_512_bytes(min, 64, kr);
  kpke_encrypt(pk, msg, kr + 32, ct);
  r = k_hex_out_cat(ct, 1088, kr, 32);
  crypto_secure_wipe(msg, sizeof msg);
  crypto_secure_wipe(kr, sizeof kr);
  crypto_secure_wipe(min, sizeof min);
  crypto_secure_wipe(h, sizeof h);
  return r;
}

/* ML-KEM.Decaps(dk, c) with implicit rejection. K = SHA3-512(m' || H(ek))
 * then constant-time compare c' = KPKE.Encrypt(ek, m', K[32:]) against c.
 * If equal, output K[:32]; else output SHAKE256(z || c) (the rejection
 * key). Constant-time over the equality check.
 * Returns hex(K) = 64 hex chars, or "" on input failure. */
OoStr crypto_mlkem768_decaps_internal(OoStr dk, OoStr ct_in) {
  uint8_t sk[2400], ct[1088], m[32], cmp[1088], kr[64], h[32], min[64], kbar[32];
  const uint8_t *pk, *z;
  OoStr r;
  memset(sk, 0, sizeof sk); memset(m, 0, sizeof m); memset(kr, 0, sizeof kr);
  memset(min, 0, sizeof min); memset(kbar, 0, sizeof kbar);
  if (!k_hex_load(dk, sk, 2400)) {
    crypto_secure_wipe(sk, sizeof sk);
    return oo_str_lit("");
  }
  if (!k_hex_load(ct_in, ct, 1088)) {
    crypto_secure_wipe(sk, sizeof sk);
    return oo_str_lit("");
  }
  kpke_decrypt(sk, ct, m);
  pk = sk + 1152;
  memcpy(h, sk + 1152 + 1184, 32);
  z = sk + 1152 + 1184 + 32;
  memcpy(min, m, 32); memcpy(min + 32, h, 32);
  oo_sha3_512_bytes(min, 64, kr);
  kpke_encrypt(pk, m, kr + 32, cmp);
  {
    uint8_t fail = 0, buf[32 + 1088];
    size_t i;
    /* Constant-time compare: fail becomes 0xFF if any byte differs. */
    for (i = 0; i < 1088; i++) fail |= (uint8_t)(ct[i] ^ cmp[i]);
    memcpy(buf, z, 32); memcpy(buf + 32, ct, 1088);
    oo_shake256(buf, 32 + 1088, kbar, 32);
    fail = (uint8_t)((-fail) >> 8);
    for (i = 0; i < 32; i++) kr[i] = (uint8_t)((kr[i] & ~fail) | (kbar[i] & fail));
    crypto_secure_wipe(buf, sizeof buf);
  }
  r = k_hex_out(kr, 32);
  crypto_secure_wipe(sk, sizeof sk);
  crypto_secure_wipe(m, sizeof m);
  crypto_secure_wipe(kr, sizeof kr);
  crypto_secure_wipe(min, sizeof min);
  crypto_secure_wipe(kbar, sizeof kbar);
  crypto_secure_wipe(h, sizeof h);
  crypto_secure_wipe(cmp, sizeof cmp);
  return r;
}
