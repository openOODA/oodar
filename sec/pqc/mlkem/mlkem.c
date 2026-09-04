/* FIPS 203 ML-KEM-768 — orchestrator (keygen path). NTT/sampling/byte
 * conversions and KEM encaps/decaps live in sibling files in this subdir.
 *
 * Public API (declared in sec/crypto/crypto_internal.h):
 *   OoStr crypto_mlkem768_keygen_internal(OoStr dz);
 *
 * dz is the seed d(32)||z(32) as 64 raw bytes or 128 hex chars.
 * Returns hex(pk || sk) = (1184 + 2400) * 2 = 7168 hex chars, or "" on failure.
 */
#include "../../../oodar.h"
#include <stdint.h>

/* FIPS 203 §8 parameter set ML-KEM-768. */
#define KK 3
#define KQ 3329
#define KN 256

/* Forward decls of SHA3 family + KPKE keygen primitive. */
void oo_sha3_256_bytes(const uint8_t *in, size_t n, uint8_t out[32]);
void oo_sha3_512_bytes(const uint8_t *in, size_t n, uint8_t out[64]);
void oo_shake128(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void kpke_keygen(const uint8_t d[32], uint8_t pk[1184], uint8_t skc[1152]);

/* keygen: input d(32)||z(32) raw or hex. output pk||sk hex.
 * ML-KEM key layout:
 *   sk (2400 bytes) = skc (1152, KPKE secret) || pk (1184) || H(pk) (32) || z (32)
 * See FIPS 203 §6.1 (K-PKE.KeyGen) + §6.2 (ML-KEM.KeyGen).
 *
 * Hex I/O glue (k_hex_load / k_hex_out / k_hex_out_cat) lives in
 * mlkem_internal.c with external linkage so the sibling KEM file can share it. */
OoStr crypto_mlkem768_keygen_internal(OoStr dz);
extern int k_hex_load(OoStr s, uint8_t *out, size_t want);
extern OoStr k_hex_out(const uint8_t *p, size_t n);
extern OoStr k_hex_out_cat(const uint8_t *a, size_t na, const uint8_t *b, size_t nb);

OoStr crypto_mlkem768_keygen_internal(OoStr dz) {
  uint8_t buf[64], pk[1184], sk[2400], h[32];
  OoStr r;
  memset(buf, 0, sizeof buf); memset(sk, 0, sizeof sk);
  if (!k_hex_load(dz, buf, 64)) {
    crypto_secure_wipe(buf, sizeof buf);
    return oo_str_lit("");
  }
  kpke_keygen(buf, pk, sk);
  memcpy(sk + 1152, pk, 1184);
  oo_sha3_256_bytes(pk, 1184, h);
  memcpy(sk + 1152 + 1184, h, 32);
  memcpy(sk + 1152 + 1184 + 32, buf + 32, 32);
  r = k_hex_out_cat(pk, 1184, sk, 2400);
  crypto_secure_wipe(buf, sizeof buf);
  crypto_secure_wipe(sk, sizeof sk);
  crypto_secure_wipe(h, sizeof h);
  return r;
}
