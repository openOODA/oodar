/* FIPS 204 ML-DSA-65 — sign operation + signature encoding.
 *
 * Public API (declared in sec/crypto/crypto_internal.h):
 *   OoStr crypto_mldsa65_sign_internal(OoStr sk, OoStr msg, OoStr rnd);
 *
 * Returns hex(sig) = 3309 * 2 = 6618 hex chars, or "" on failure.
 *
 * This TU owns the d_sign_internal rejection-sampling loop and the
 * constant-time signature packing (d_pack_sig). The underlying NTT,
 * sampling, and byte conversions live in mldsa_internal.c.
 */
#include "../../../oodar.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* FIPS 204 §5 parameter set ML-DSA-65. */
#define DPK 1952
#define DSK 4032
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
#define DSEED 32
#define DTR 64

/* Forward decls of SHAKE family. */
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void oo_shake128(const uint8_t *in, size_t n, uint8_t *out, size_t outn);

/* Primitives from mldsa_internal.c. */
void d_unpack_sk(uint8_t rho[32], uint8_t tr[64], uint8_t key[32],
                 int32_t t0[DK][256], int32_t s1[DL][256], int32_t s2[DK][256],
                 const uint8_t sk[DSK]);
void d_expand_a(int32_t mat[DK][DL][256], const uint8_t rho[32]);
void d_ntt(int32_t a[256]);
void d_invntt(int32_t a[256]);
void d_poly_reduce(int32_t a[256]);
void d_poly_caddq(int32_t a[256]);
void d_poly_add(int32_t c[256], const int32_t a[256], const int32_t b[256]);
void d_poly_sub(int32_t c[256], const int32_t a[256], const int32_t b[256]);
void d_poly_pointwise(int32_t c[256], const int32_t a[256], const int32_t b[256]);
void d_poly_uniform_gamma1(int32_t a[256], const uint8_t seed[64], uint16_t nonce);
void d_matrix_pointwise(int32_t t[DK][256], int32_t mat[DK][DL][256], int32_t v[DL][256]);
int32_t d_decompose(int32_t *a0, int32_t a);
void d_polyw1_pack(uint8_t *r, const int32_t a[256]);
void d_poly_challenge(int32_t c[256], const uint8_t seed[48]);
int d_chknorm(const int32_t a[256], int32_t B);
unsigned int d_make_hint(int32_t a0, int32_t a1);
void d_pack_sig(uint8_t sig[DSIG], const uint8_t c[DCTILDE], int32_t z[DL][256], int32_t h[DK][256]);
void d_polyz_pack(uint8_t *r, const int32_t a[256]);

/* Hex I/O glue (mldsa_internal.c) — shared with mldsa.c and mldsa_verify.c. */
extern int d_hex_digit(char c);
extern int d_hex_load(OoStr s, uint8_t *out, size_t want);
extern OoStr d_hex_out(const uint8_t *p, size_t n);
extern int d_load_msg(OoStr s, uint8_t *out, size_t *n, size_t maxn);

/* FIPS 204 §6.2 (ML-DSA.Sign). Rejection-sampling loop with up to 10000
 * attempts; fails closed if no signature is produced. */
static int d_sign_internal(uint8_t sig[DSIG], const uint8_t *m, size_t mlen,
                           const uint8_t rnd[32], const uint8_t sk[DSK]) {
  uint8_t rho[32], tr[64], key[32], mu[64], rhoprime[64], w1pack[DK * DPOLYW1];
  int32_t mat[DK][DL][256], s1[DL][256], y[DL][256], z[DL][256];
  int32_t t0[DK][256], s2[DK][256], w1[DK][256], w0[DK][256], h[DK][256], cp[256];
  uint16_t nonce = 0;
  unsigned int i, n, tries;
  uint8_t *concat;
  d_unpack_sk(rho, tr, key, t0, s1, s2, sk);
  concat = (uint8_t *)malloc(64 + mlen);
  if (!concat) return -1;
  memcpy(concat, tr, 64);
  if (mlen) memcpy(concat + 64, m, mlen);
  oo_shake256(concat, 64 + mlen, mu, 64);
  free(concat);
  {
    uint8_t in[32 + 32 + 64];
    memcpy(in, key, 32);
    memcpy(in + 32, rnd, 32);
    memcpy(in + 64, mu, 64);
    oo_shake256(in, 128, rhoprime, 64);
  }
  d_expand_a(mat, rho);
  for (i = 0; i < DL; i++) d_ntt(s1[i]);
  for (i = 0; i < DK; i++) { d_ntt(s2[i]); d_ntt(t0[i]); }
  for (tries = 0; tries < 10000; tries++) {
    int reject = 0;
    for (i = 0; i < DL; i++) d_poly_uniform_gamma1(y[i], rhoprime, nonce++);
    for (i = 0; i < DL; i++) { memcpy(z[i], y[i], sizeof y[i]); d_ntt(z[i]); }
    d_matrix_pointwise(w1, mat, z);
    for (i = 0; i < DK; i++) { d_poly_reduce(w1[i]); d_invntt(w1[i]); d_poly_caddq(w1[i]); }
    for (i = 0; i < DK; i++) {
      unsigned int j;
      for (j = 0; j < 256; j++) w1[i][j] = d_decompose(&w0[i][j], w1[i][j]);
    }
    for (i = 0; i < DK; i++) d_polyw1_pack(w1pack + i * DPOLYW1, w1[i]);
    {
      uint8_t in[64 + DK * DPOLYW1];
      memcpy(in, mu, 64);
      memcpy(in + 64, w1pack, DK * DPOLYW1);
      oo_shake256(in, 64 + DK * DPOLYW1, sig, DCTILDE);
    }
    d_poly_challenge(cp, sig);
    d_ntt(cp);
    for (i = 0; i < DL; i++) {
      d_poly_pointwise(z[i], cp, s1[i]);
      d_invntt(z[i]);
      d_poly_add(z[i], z[i], y[i]);
      d_poly_reduce(z[i]);
      if (d_chknorm(z[i], DGAMMA1 - DBETA)) reject = 1;
    }
    if (reject) continue;
    for (i = 0; i < DK; i++) {
      d_poly_pointwise(h[i], cp, s2[i]);
      d_invntt(h[i]);
      d_poly_sub(w0[i], w0[i], h[i]);
      d_poly_reduce(w0[i]);
      if (d_chknorm(w0[i], DGAMMA2 - DBETA)) reject = 1;
    }
    if (reject) continue;
    n = 0;
    for (i = 0; i < DK; i++) {
      unsigned int j;
      d_poly_pointwise(h[i], cp, t0[i]);
      d_invntt(h[i]);
      d_poly_reduce(h[i]);
      if (d_chknorm(h[i], DGAMMA2)) { reject = 1; break; }
      d_poly_add(w0[i], w0[i], h[i]);
      for (j = 0; j < 256; j++) {
        h[i][j] = (int32_t)d_make_hint(w0[i][j], w1[i][j]);
        n += (unsigned int)h[i][j];
      }
    }
    if (reject || n > DOMEGA) continue;
    d_pack_sig(sig, sig, z, h);
    return 0;
  }
  return -1;
}

/* crypto_mldsa65_sign_internal: sk||msg||rnd → sig hex. The rnd arg is
 * optional (pass OoStr with data=NULL/len=0 for deterministic sign). */
OoStr crypto_mldsa65_sign_internal(OoStr sk, OoStr msg, OoStr rnd) {
  uint8_t skb[DSK], rndb[32], sig[DSIG], mbuf[4096];
  size_t mn;
  OoStr r;
  memset(rndb, 0, 32); memset(skb, 0, sizeof skb); memset(mbuf, 0, sizeof mbuf);
  if (!d_hex_load(sk, skb, DSK)) {
    crypto_secure_wipe(skb, sizeof skb);
    crypto_secure_wipe(rndb, sizeof rndb);
    return oo_str_lit("");
  }
  if (!d_load_msg(msg, mbuf, &mn, sizeof mbuf)) {
    crypto_secure_wipe(skb, sizeof skb);
    crypto_secure_wipe(rndb, sizeof rndb);
    crypto_secure_wipe(mbuf, sizeof mbuf);
    return oo_str_lit("");
  }
  if (rnd.data && rnd.len > 0) {
    if (!d_hex_load(rnd, rndb, 32) && rnd.len == 32) memcpy(rndb, rnd.data, 32);
  }
  if (d_sign_internal(sig, mbuf, mn, rndb, skb) != 0) {
    crypto_secure_wipe(skb, sizeof skb);
    crypto_secure_wipe(rndb, sizeof rndb);
    crypto_secure_wipe(mbuf, sizeof mbuf);
    return oo_str_lit("");
  }
  r = d_hex_out(sig, DSIG);
  crypto_secure_wipe(skb, sizeof skb);
  crypto_secure_wipe(rndb, sizeof rndb);
  crypto_secure_wipe(mbuf, sizeof mbuf);
  return r;
}
