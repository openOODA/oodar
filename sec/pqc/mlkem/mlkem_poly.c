#include "mlkem_internal.h"
  unsigned int i, j;
  for (i = 0; i < 32; i++) {
    for (j = 0; j < 8; j++) {
      int16_t mask = (int16_t)(-((int16_t)((msg[i] >> j) & 1)));
      r[8 * i + j] = (int16_t)(mask & ((KQ + 1) / 2));
    }
  }
}
static void k_poly_tomsg(uint8_t msg[32], const int16_t a[256]) {
  k_poly_compress(msg, a, 1);
}

static void k_poly_encode12(uint8_t *r, const int16_t a[256]) {
  unsigned int i;
  uint16_t t0, t1;
  for (i = 0; i < 128; i++) {
    t0 = (uint16_t)a[2 * i];
    t0 = (uint16_t)(t0 + (((int16_t)t0 >> 15) & KQ));
    t1 = (uint16_t)a[2 * i + 1];
    t1 = (uint16_t)(t1 + (((int16_t)t1 >> 15) & KQ));
    r[3 * i + 0] = (uint8_t)(t0 >> 0);
    r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
    r[3 * i + 2] = (uint8_t)(t1 >> 4);
  }
}
static void k_poly_decode12(int16_t r[256], const uint8_t *a) {
  unsigned int i;
  for (i = 0; i < 128; i++) {
    r[2 * i] = (int16_t)((a[3 * i + 0] | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF);
    r[2 * i + 1] = (int16_t)(((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF);
  }
}

/* === Matrix generation, eta noise, byte <-> public/secret key. === */

static void k_gen_matrix(int16_t a[KK][KK][256], const uint8_t rho[32], int transposed) {
  int i, j;
  uint8_t seed[34];
  memcpy(seed, rho, 32);
  for (i = 0; i < KK; i++) {
    for (j = 0; j < KK; j++) {
      seed[32] = (uint8_t)(transposed ? i : j);
      seed[33] = (uint8_t)(transposed ? j : i);
      k_sample_ntt(a[i][j], seed);
    }
  }
}

static void k_getnoise_eta1(int16_t r[256], const uint8_t seed[32], uint8_t nonce) {
  uint8_t buf[128];
  k_prf(buf, 128, seed, nonce);
  k_cbd2(r, buf);
}
static void k_getnoise_eta2(int16_t r[256], const uint8_t seed[32], uint8_t nonce) {
  k_getnoise_eta1(r, seed, nonce);
}

static void k_pk_frombytes(int16_t pk[KK][256], uint8_t rho[32], const uint8_t *pkbytes) {
  int i;
  for (i = 0; i < KK; i++) k_poly_decode12(pk[i], pkbytes + i * 384);
  memcpy(rho, pkbytes + KK * 384, 32);
}
static void k_sk_frombytes(int16_t sk[KK][256], const uint8_t *skbytes) {
  int i;
  for (i = 0; i < KK; i++) k_poly_decode12(sk[i], skbytes + i * 384);
}

/* === KPKE.KeyGen / Encrypt / Decrypt (FIPS 203 §6.1, §6.2.1, §6.2.2). === */

void kpke_keygen(const uint8_t d[32], uint8_t pk[1184], uint8_t skc[1152]) {
  uint8_t buf[64], rho[32], sigma[32];
  int16_t a[KK][KK][256], s[KK][256], e[KK][256], t[KK][256], tmp[256];
  int i, j;
  uint8_t dn[33];
  memcpy(dn, d, 32); dn[32] = (uint8_t)KK;
  oo_sha3_512_bytes(dn, 33, buf);
  memcpy(rho, buf, 32); memcpy(sigma, buf + 32, 32);
  k_gen_matrix(a, rho, 0);
  for (i = 0; i < KK; i++) k_getnoise_eta1(s[i], sigma, (uint8_t)i);
  for (i = 0; i < KK; i++) k_getnoise_eta1(e[i], sigma, (uint8_t)(i + KK));
  for (i = 0; i < KK; i++) { k_ntt(s[i]); k_ntt(e[i]); k_poly_reduce(s[i]); }
  for (i = 0; i < KK; i++) {
    memset(t[i], 0, sizeof t[i]);
    for (j = 0; j < KK; j++) {
      k_poly_mul(tmp, a[i][j], s[j]);
      k_poly_add(t[i], t[i], tmp);
    }
    k_poly_reduce(t[i]);
    k_poly_tomont(t[i]);
    k_poly_add(t[i], t[i], e[i]);
    k_poly_reduce(t[i]);
  }
  for (i = 0; i < KK; i++) k_poly_encode12(skc + i * 384, s[i]);
  for (i = 0; i < KK; i++) k_poly_encode12(pk + i * 384, t[i]);
  memcpy(pk + KK * 384, rho, 32);
}

void kpke_encrypt(const uint8_t pk[1184], const uint8_t m[32], const uint8_t coins[32], uint8_t c[1088]) {
  uint8_t rho[32];
  int16_t pkpv[KK][256], at[KK][KK][256], sp[KK][256], ep[KK][256], bp[KK][256];
  int16_t v[256], kpoly[256], epp[256], tmp[256];
  int i, j;
  k_pk_frombytes(pkpv, rho, pk);
  k_gen_matrix(at, rho, 1);
  for (i = 0; i < KK; i++) k_getnoise_eta1(sp[i], coins, (uint8_t)i);
  for (i = 0; i < KK; i++) k_getnoise_eta2(ep[i], coins, (uint8_t)(i + KK));
  k_getnoise_eta2(epp, coins, (uint8_t)(2 * KK));
  for (i = 0; i < KK; i++) k_ntt(sp[i]);
  for (i = 0; i < KK; i++) {
    memset(bp[i], 0, sizeof bp[i]);
    for (j = 0; j < KK; j++) {
      k_poly_mul(tmp, at[i][j], sp[j]);
      k_poly_add(bp[i], bp[i], tmp);
    }
    k_poly_reduce(bp[i]);
    k_invntt(bp[i]);
    k_poly_add(bp[i], bp[i], ep[i]);
    k_poly_reduce(bp[i]);
  }
  memset(v, 0, sizeof v);
  for (i = 0; i < KK; i++) {
    k_poly_mul(tmp, pkpv[i], sp[i]);
    k_poly_add(v, v, tmp);
  }
  k_poly_reduce(v);
  k_invntt(v);
  k_poly_frommsg(kpoly, m);
  k_poly_add(v, v, epp);
  k_poly_add(v, v, kpoly);
  k_poly_reduce(v);
  for (i = 0; i < KK; i++) k_poly_compress(c + i * 320, bp[i], KDU);
  k_poly_compress(c + KK * 320, v, KDV);
}

void kpke_decrypt(const uint8_t skc[1152], const uint8_t c[1088], uint8_t m[32]) {
  int16_t bp[KK][256], v[256], skpv[KK][256], mp[256], tmp[256];
  int i;
  for (i = 0; i < KK; i++) k_poly_decompress(bp[i], c + i * 320, KDU);
  k_poly_decompress(v, c + KK * 320, KDV);
  k_sk_frombytes(skpv, skc);
  for (i = 0; i < KK; i++) k_ntt(bp[i]);
  memset(mp, 0, sizeof mp);
  for (i = 0; i < KK; i++) {
    k_poly_mul(tmp, skpv[i], bp[i]);
    k_poly_add(mp, mp, tmp);
  }
  k_poly_reduce(mp);
  k_invntt(mp);
  k_poly_sub(mp, v, mp);
  k_poly_reduce(mp);
  k_poly_tomsg(m, mp);
}
