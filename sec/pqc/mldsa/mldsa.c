/* FIPS 204 ML-DSA-65 (Dilithium3) — orchestrator (keygen path).
 * Sign/verify live in sibling files in this subdir. NTT, sampling,
 * rejection sampling, and byte conversions live in mldsa_internal.c.
 *
 * Public API (declared in sec/crypto/crypto_internal.h):
 *   OoStr crypto_mldsa65_keygen_internal(OoStr seed);
 *
 * seed is the 32-byte ξ as 32 raw bytes or 64 hex chars.
 * Returns hex(pk || sk) = (1952 + 4032) * 2 = 11968 hex chars, or "" on failure.
 */
#include "../../../oodar.h"
#include <stdint.h>
#include <string.h>

/* FIPS 204 §5 parameter set ML-DSA-65. */
#define DPK 1952
#define DSK 4032

/* Forward decls of SHAKE family + keygen primitive. */
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void oo_shake128(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void d_keygen(const uint8_t xi[32], uint8_t pk[DPK], uint8_t sk[DSK]);

/* Hex I/O glue (mldsa_internal.c) — external linkage shared with sign/verify. */
extern int d_hex_digit(char c);
extern int d_hex_load(OoStr s, uint8_t *out, size_t want);
extern OoStr d_hex_out(const uint8_t *p, size_t n);
extern OoStr d_hex_out_cat(const uint8_t *a, size_t na, const uint8_t *b, size_t nb);

/* crypto_mldsa65_keygen_internal: 32-byte seed → pk||sk hex.
 * FIPS 204 §6.1 (ML-DSA.KeyGen). */
OoStr crypto_mldsa65_keygen_internal(OoStr seed) {
  uint8_t xi[32], pk[DPK], sk[DSK];
  OoStr r;
  memset(xi, 0, sizeof xi); memset(sk, 0, sizeof sk);
  if (!d_hex_load(seed, xi, 32)) {
    crypto_secure_wipe(xi, sizeof xi);
    return oo_str_lit("");
  }
  d_keygen(xi, pk, sk);
  r = d_hex_out_cat(pk, DPK, sk, DSK);
  crypto_secure_wipe(xi, sizeof xi);
  crypto_secure_wipe(sk, sizeof sk);
  return r;
}
