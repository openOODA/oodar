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
