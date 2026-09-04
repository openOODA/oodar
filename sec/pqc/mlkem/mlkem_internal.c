/* FIPS 203 ML-KEM-768 — internal primitives. NTT, sampling, byte
 * conversions, and the KPKE.KeyGen/Encrypt/Decrypt used by the
 * orchestrator (mlkem.c) and the KEM ops (mlkem_kem.c).
 *
 * The public surface here is non-static: kpke_keygen, kpke_encrypt,
 * kpke_decrypt are called across the mlkem/ subdir, so they have
 * external linkage. Everything else is module-local.
 */
#include "../../../oodar.h"
#include <stdint.h>

/* FIPS 203 §8 parameter set ML-KEM-768. */
#define KQ 3329
#define KN 256
#define KK 3
#define KETA1 2
#define KETA2 2
#define KDU 10
#define KDV 4

void oo_sha3_256_bytes(const uint8_t *in, size_t n, uint8_t out[32]);
void oo_sha3_512_bytes(const uint8_t *in, size_t n, uint8_t out[64]);
void oo_shake128(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn);

/* Zetas for the in-place Cooley-Tukey NTT. FIPS 203 §4.4 / pq-crystals ref. */
static const int16_t k_zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

/* === Hex I/O glue shared with mlkem.c (orchestrator) and mlkem_kem.c.
 * External linkage so sibling TUs in this subdir can call these without
 * relying on umbrella include order. === */

int k_hex_load(OoStr s, uint8_t *out, size_t want) {
  size_t i, n;
  if (!s.data || s.len < 0) return 0;
  n = (size_t)s.len;
  if (n == want) { memcpy(out, s.data, want); return 1; }
  if (n == want * 2) {
    for (i = 0; i < want; i++) {
      int hi, lo;
      char c = s.data[2 * i], d = s.data[2 * i + 1];
      hi = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
      lo = (d >= '0' && d <= '9') ? d - '0' : (d >= 'a' && d <= 'f') ? d - 'a' + 10 : (d >= 'A' && d <= 'F') ? d - 'A' + 10 : -1;
      if (hi < 0 || lo < 0) return 0;
      out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
  }
  return 0;
}

OoStr k_hex_out(const uint8_t *p, size_t n) {
  static const char *hx = "0123456789abcdef";
  char *buf = oo_str_alloc_payload(n * 2);
  size_t i;
  for (i = 0; i < n; i++) { buf[i * 2] = hx[(p[i] >> 4) & 0xf]; buf[i * 2 + 1] = hx[p[i] & 0xf]; }
  { OoStr r; r.data = buf; r.len = (long long)(n * 2); return r; }
}

OoStr k_hex_out_cat(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
  static const char *hx = "0123456789abcdef";
  size_t n = na + nb, i;
  char *buf = oo_str_alloc_payload(n * 2);
  for (i = 0; i < na; i++) { buf[i * 2] = hx[(a[i] >> 4) & 0xf]; buf[i * 2 + 1] = hx[a[i] & 0xf]; }
  for (i = 0; i < nb; i++) { buf[(na + i) * 2] = hx[(b[i] >> 4) & 0xf]; buf[(na + i) * 2 + 1] = hx[b[i] & 0xf]; }
  { OoStr r; r.data = buf; r.len = (long long)(n * 2); return r; }
}

/* === Field arithmetic: Montgomery, Barrett, FqMul. === */

static int16_t k_montgomery(int32_t a) {
  /* QINV = q^{-1} mod 2^16 = -3327 (pq-crystals / FIPS 203 Montgomery). */
  int16_t t = (int16_t)a * (int16_t)(-3327);
  t = (int16_t)((a - (int32_t)t * KQ) >> 16);
  return t;
}
static int16_t k_barrett(int16_t a) {
  int16_t t = (int16_t)(((int32_t)20159 * a + (1 << 25)) >> 26);
  return (int16_t)(a - t * KQ);
}
static int16_t k_fqmul(int16_t a, int16_t b) {
  return k_montgomery((int32_t)a * b);
}

/* === NTT / inverse NTT. === */

static void k_ntt(int16_t r[256]) {
  unsigned int len, start, j, k = 1;
  for (len = 128; len >= 2; len >>= 1) {
    for (start = 0; start < 256; start = j + len) {
      int16_t zeta = k_zetas[k++];
      for (j = start; j < start + len; j++) {
        int16_t t = k_fqmul(zeta, r[j + len]);
        r[j + len] = (int16_t)(r[j] - t);
        r[j] = (int16_t)(r[j] + t);
      }
    }
  }
  for (j = 0; j < 256; j++) r[j] = k_barrett(r[j]);
}

static void k_invntt(int16_t r[256]) {
  unsigned int start, len, j, k = 127;
  const int16_t f = 1441;
  for (len = 2; len <= 128; len <<= 1) {
    for (start = 0; start < 256; start = j + len) {
      int16_t zeta = k_zetas[k--];
      for (j = start; j < start + len; j++) {
        int16_t t = r[j];
        r[j] = k_barrett((int16_t)(t + r[j + len]));
        r[j + len] = (int16_t)(r[j + len] - t);
        r[j + len] = k_fqmul(zeta, r[j + len]);
      }
    }
  }
  for (j = 0; j < 256; j++) r[j] = k_fqmul(r[j], f);
}

static void k_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
  r[0] = k_fqmul(k_fqmul(a[1], b[1]), zeta);
  r[0] = (int16_t)(r[0] + k_fqmul(a[0], b[0]));
  r[1] = (int16_t)(k_fqmul(a[0], b[1]) + k_fqmul(a[1], b[0]));
}

static void k_poly_mul(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
  unsigned int i;
  for (i = 0; i < 64; i++) {
    k_basemul(&r[4 * i], &a[4 * i], &b[4 * i], k_zetas[64 + i]);
    k_basemul(&r[4 * i + 2], &a[4 * i + 2], &b[4 * i + 2], (int16_t)(-k_zetas[64 + i]));
  }
}

static void k_poly_add(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
  int i; for (i = 0; i < 256; i++) r[i] = (int16_t)(a[i] + b[i]);
}
static void k_poly_sub(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
  int i; for (i = 0; i < 256; i++) r[i] = (int16_t)(a[i] - b[i]);
}
static void k_poly_reduce(int16_t r[256]) {
  int i; for (i = 0; i < 256; i++) r[i] = k_barrett(r[i]);
}
static void k_poly_tomont(int16_t r[256]) {
  const int16_t f = (1ULL << 32) % KQ;
  int i; for (i = 0; i < 256; i++) r[i] = k_montgomery((int32_t)r[i] * f);
}

/* === 24-bit and 32-bit little-endian byte loaders (FIPS 203 §4.2.1). === */

static uint32_t k_load24(const uint8_t *x) {
  uint32_t r = x[0]; r |= (uint32_t)x[1] << 8; r |= (uint32_t)x[2] << 16; return r;
}
static uint32_t k_load32(const uint8_t *x) {
  uint32_t r = x[0]; r |= (uint32_t)x[1] << 8; r |= (uint32_t)x[2] << 16; r |= (uint32_t)x[3] << 24; return r;
}

/* === Sampling: CBD (centered binomial), NTT-domain rejection, PRF. === */

static void k_cbd2(int16_t r[256], const uint8_t buf[128]) {
  unsigned int i, j;
  for (i = 0; i < 32; i++) {
    uint32_t t = (uint32_t)buf[4 * i] | ((uint32_t)buf[4 * i + 1] << 8)
               | ((uint32_t)buf[4 * i + 2] << 16) | ((uint32_t)buf[4 * i + 3] << 24);
    uint32_t d = t & 0x55555555u;
    d += (t >> 1) & 0x55555555u;
    for (j = 0; j < 8; j++) {
      int16_t a = (int16_t)((d >> (4 * j + 0)) & 0x3);
      int16_t b = (int16_t)((d >> (4 * j + 2)) & 0x3);
      r[8 * i + j] = (int16_t)(a - b);
    }
  }
}

static void k_sample_ntt(int16_t r[256], const uint8_t seed[34]) {
  uint8_t buf[168];
  /* SHAKE-128 absorb seed||i||j then squeeze; we implement via a streaming-less pull. */
  /* Rejection: request blocks of 168 bytes. */
  {
    uint8_t stin[34];
    size_t off = 0, ctr = 0;
    memcpy(stin, seed, 34);
    /* Use incremental squeeze by re-invoking shake on expanding output via a local keccak is heavy;
       instead squeeze a large buffer. Worst-case ~704 bytes. */
    {
      uint8_t big[840];
      oo_shake128(stin, 34, big, sizeof big);
      while (ctr < 256 && off + 3 <= sizeof big) {
        uint16_t d1 = (uint16_t)(big[off] | ((uint16_t)(big[off + 1] & 0x0f) << 8));
        uint16_t d2 = (uint16_t)((big[off + 1] >> 4) | ((uint16_t)big[off + 2] << 4));
        off += 3;
        if (d1 < KQ && ctr < 256) r[ctr++] = (int16_t)d1;
        if (d2 < KQ && ctr < 256) r[ctr++] = (int16_t)d2;
      }
    }
  }
}

static void k_prf(uint8_t *out, size_t outn, const uint8_t seed[64], uint8_t nonce) {
  uint8_t ext[33];
  memcpy(ext, seed, 32); ext[32] = nonce;
  oo_shake256(ext, 33, out, outn);
}

static int16_t k_decompress(int16_t y, int d) {
  return (int16_t)(((uint32_t)y * KQ + (1u << (d - 1))) >> d);
}

/* === Byte <-> polynomial conversion (compress / decompress / 12-bit). === */

static void k_poly_compress(uint8_t *r, const int16_t a[256], int d) {
  unsigned int i, j;
  if (d == 4) {
    for (i = 0; i < 32; i++) {
      uint8_t t[8];
      for (j = 0; j < 8; j++) {
        int32_t u = a[8 * i + j];
        uint32_t d0;
        u += (u >> 15) & KQ;
        d0 = (uint32_t)u << 4;
        d0 += 1665;
        d0 *= 80635;
        d0 >>= 28;
        t[j] = (uint8_t)(d0 & 0xf);
      }
      r[0] = (uint8_t)(t[0] | (t[1] << 4));
      r[1] = (uint8_t)(t[2] | (t[3] << 4));
      r[2] = (uint8_t)(t[4] | (t[5] << 4));
      r[3] = (uint8_t)(t[6] | (t[7] << 4));
      r += 4;
    }
  } else if (d == 10) {
    for (i = 0; i < 64; i++) {
      uint16_t t[4];
      uint64_t d0;
      unsigned int k;
      for (k = 0; k < 4; k++) {
        t[k] = (uint16_t)a[4 * i + k];
        t[k] = (uint16_t)(t[k] + (((int16_t)t[k] >> 15) & KQ));
        d0 = t[k];
        d0 <<= 10;
        d0 += 1665;
        d0 *= 1290167ULL;
        d0 >>= 32;
        t[k] = (uint16_t)(d0 & 0x3ff);
      }
      r[0] = (uint8_t)(t[0] >> 0);
      r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
      r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
      r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
      r[4] = (uint8_t)(t[3] >> 2);
      r += 5;
    }
  } else if (d == 1) {
    for (i = 0; i < 32; i++) {
      r[i] = 0;
      for (j = 0; j < 8; j++) {
        uint32_t t = (uint32_t)a[8 * i + j];
        t <<= 1;
        t += 1665;
        t *= 80635;
        t >>= 28;
        r[i] |= (uint8_t)((t & 1) << j);
      }
    }
  }
}

static void k_poly_decompress(int16_t r[256], const uint8_t *a, int d) {
  int i, j;
  if (d == 4) {
    for (i = 0; i < 128; i++) {
      r[2 * i] = k_decompress((int16_t)(a[i] & 15), 4);
      r[2 * i + 1] = k_decompress((int16_t)(a[i] >> 4), 4);
    }
  } else if (d == 10) {
    int k = 0;
    for (i = 0; i < 64; i++) {
      uint16_t t[4];
      t[0] = (uint16_t)(a[k] | ((uint16_t)(a[k + 1] & 0x03) << 8));
      t[1] = (uint16_t)((a[k + 1] >> 2) | ((uint16_t)(a[k + 2] & 0x0f) << 6));
      t[2] = (uint16_t)((a[k + 2] >> 4) | ((uint16_t)(a[k + 3] & 0x3f) << 4));
      t[3] = (uint16_t)((a[k + 3] >> 6) | ((uint16_t)a[k + 4] << 2));
      k += 5;
      for (j = 0; j < 4; j++) r[4 * i + j] = k_decompress((int16_t)(t[j] & 0x3ff), 10);
    }
  } else if (d == 1) {
    for (i = 0; i < 32; i++)
      for (j = 0; j < 8; j++) r[8 * i + j] = k_decompress((int16_t)((a[i] >> j) & 1), 1);
  }
}

static void k_poly_frommsg(int16_t r[256], const uint8_t msg[32]) {
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
