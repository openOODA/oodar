/* FIPS 204 ML-DSA-65 — verify operation + signature unpacking.
 *
 * Public API (declared in sec/crypto/crypto_internal.h):
 *   OoStr crypto_mldsa65_verify_internal(OoStr pk, OoStr msg, OoStr sig);
 *
 * Returns "OK" iff the signature verifies, or "" on failure / bad inputs.
 *
 * This TU owns d_verify_internal and d_unpack_sig (with its sorted-hint
 * validity checks). The underlying NTT, sampling, and byte conversions
 * live in mldsa_internal.c.
 */
#include "../../../oodar.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* FIPS 204 §5 parameter set ML-DSA-65. */
#define DPK 1952
#define DSIG 3309
#define DPOLYZ 640
#define DPOLYW1 128
#define DK 6
#define DL 5
#define DTAU 49
#define DETA 4
#define DBETA 196
#define DGAMMA1 (1 << 19)
#define DGAMMA2 261888
#define DOMEGA 55
#define DD 13
#define DCTILDE 48
#define DTR 64
#define DN 256

/* Forward decls of SHAKE family. */
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void oo_shake128(const uint8_t *in, size_t n, uint8_t *out, size_t outn);

/* Primitives from mldsa_internal.c. */
void d_unpack_pk(uint8_t rho[32], int32_t t1[DK][256], const uint8_t pk[DPK]);
int d_unpack_sig(uint8_t c[DCTILDE], int32_t z[DL][256], int32_t h[DK][256], const uint8_t sig[DSIG]);
int d_chknorm(const int32_t a[256], int32_t B);
void d_expand_a(int32_t mat[DK][DL][256], const uint8_t rho[32]);
void d_ntt(int32_t a[256]);
void d_invntt(int32_t a[256]);
void d_poly_shiftl(int32_t a[256]);
void d_poly_pointwise(int32_t c[256], const int32_t a[256], const int32_t b[256]);
void d_poly_sub(int32_t c[256], const int32_t a[256], const int32_t b[256]);
void d_poly_reduce(int32_t a[256]);
void d_poly_caddq(int32_t a[256]);
void d_poly_add(int32_t c[256], const int32_t a[256], const int32_t b[256]);
void d_poly_challenge(int32_t c[256], const uint8_t seed[48]);
void d_matrix_pointwise(int32_t t[DK][256], int32_t mat[DK][DL][256], int32_t v[DL][256]);
int32_t d_use_hint(int32_t a, unsigned int hint);
void d_polyw1_pack(uint8_t *r, const int32_t a[256]);
void d_polyz_unpack(int32_t r[256], const uint8_t *a);

/* Hex I/O glue (mldsa_internal.c) — shared with mldsa.c and mldsa_sign.c. */
extern int d_hex_load(OoStr s, uint8_t *out, size_t want);
extern int d_load_msg(OoStr s, uint8_t *out, size_t *n, size_t maxn);

/* FIPS 204 §6.3 (ML-DSA.Verify). Returns 0 on success, -1 on failure. */
static int d_verify_internal(const uint8_t sig[DSIG], const uint8_t *m, size_t mlen, const uint8_t pk[DPK]) {
  uint8_t rho[32], mu[64], c[DCTILDE], c2[DCTILDE], w1pack[DK * DPOLYW1], tr[DTR];
  int32_t mat[DK][DL][256], z[DL][256], t1[DK][256], w1[DK][256], h[DK][256], cp[256];
  unsigned int i;
  uint8_t *concat;
  d_unpack_pk(rho, t1, pk);
  if (d_unpack_sig(c, z, h, sig)) return -1;
  for (i = 0; i < DL; i++) if (d_chknorm(z[i], DGAMMA1 - DBETA)) return -1;
  oo_shake256(pk, DPK, tr, DTR);
  concat = (uint8_t *)malloc(64 + mlen);
  if (!concat) return -1;
  memcpy(concat, tr, 64);
  if (mlen) memcpy(concat + 64, m, mlen);
  oo_shake256(concat, 64 + mlen, mu, 64);
  free(concat);
  d_poly_challenge(cp, c);
  d_expand_a(mat, rho);
  for (i = 0; i < DL; i++) d_ntt(z[i]);
  d_matrix_pointwise(w1, mat, z);
  d_ntt(cp);
  for (i = 0; i < DK; i++) {
    d_poly_shiftl(t1[i]);
    d_ntt(t1[i]);
    d_poly_pointwise(t1[i], cp, t1[i]);
    d_poly_sub(w1[i], w1[i], t1[i]);
    d_poly_reduce(w1[i]);
    d_invntt(w1[i]);
    d_poly_caddq(w1[i]);
    {
      unsigned int j;
      for (j = 0; j < 256; j++) w1[i][j] = d_use_hint(w1[i][j], (unsigned int)h[i][j]);
    }
    d_polyw1_pack(w1pack + i * DPOLYW1, w1[i]);
  }
  {
    uint8_t in[64 + DK * DPOLYW1];
    memcpy(in, mu, 64);
    memcpy(in + 64, w1pack, DK * DPOLYW1);
    oo_shake256(in, 64 + DK * DPOLYW1, c2, DCTILDE);
  }
  return crypto_ct_cmp(c, c2, DCTILDE) == 0 ? 0 : -1;
}

/* crypto_mldsa65_verify_internal: pk||msg||sig → "OK" or "".
 * The OoStr "OK" sentinel is the contract: a positive return is
 * "OK" (2 chars), anything else (including a NULL data ptr) is failure. */
OoStr crypto_mldsa65_verify_internal(OoStr pk, OoStr msg, OoStr sig) {
  uint8_t pkb[DPK], sigb[DSIG], mbuf[4096];
  size_t mn;
  int ok;
  memset(mbuf, 0, sizeof mbuf);
  if (!d_hex_load(pk, pkb, DPK)) return oo_str_lit("");
  if (!d_hex_load(sig, sigb, DSIG)) return oo_str_lit("");
  if (!d_load_msg(msg, mbuf, &mn, sizeof mbuf)) {
    crypto_secure_wipe(mbuf, sizeof mbuf);
    return oo_str_lit("");
  }
  ok = d_verify_internal(sigb, mbuf, mn, pkb);
  crypto_secure_wipe(mbuf, sizeof mbuf);
  if (ok == 0) return oo_str_lit("OK");
  return oo_str_lit("");
}
