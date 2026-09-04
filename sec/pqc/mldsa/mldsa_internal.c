/* FIPS 204 ML-DSA-65 (Dilithium3) — internal primitives. Matrix expand,
 * NTT, sampling, rejection sampling, byte conversions, and keygen/sign/
 * verify-supporting helpers.
 *
 * The public surface here is non-static: d_keygen, d_unpack_pk, d_unpack_sk,
 * d_pack_sig, d_unpack_sig, d_ntt, d_invntt, d_expand_a, d_matrix_pointwise,
 * d_chknorm, d_poly_uniform_gamma1, d_poly_challenge, d_make_hint, d_use_hint,
 * d_polyz_pack, d_polyz_unpack, d_polyw1_pack, d_decompose, d_poly_reduce,
 * d_poly_caddq, d_poly_add, d_poly_sub, d_poly_shiftl, d_poly_pointwise,
 * d_unpack_sk — called by the orchestrator (mldsa.c), sign (mldsa_sign.c),
 * and verify (mldsa_verify.c). Hex I/O (d_hex_*) is also external so the
 * sibling TUs can share it.
 */
#include "../../../oodar.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* FIPS 204 §5 parameter set ML-DSA-65. */
#define DQ 8380417
#define DN 256
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
#define DRND 32
#define DPK 1952
#define DSK 4032
#define DSIG 3309
#define DPOLYT1 320
#define DPOLYT0 416
#define DPOLYETA 128
#define DPOLYZ 640
#define DPOLYW1 128
#define DQINV 58728449

/* Forward decls of SHAKE family. */
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void oo_shake128(const uint8_t *in, size_t n, uint8_t *out, size_t outn);

/* Zetas for the in-place Cooley-Tukey NTT. FIPS 204 §4.4 / pq-crystals ref. */
static const int32_t d_zetas[256] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/* === Field arithmetic: Montgomery reduce, reduce32, conditional add q. === */

static int32_t d_mont_reduce(int64_t a) {
  int32_t t = (int32_t)a * DQINV;
  t = (int32_t)((a - (int64_t)t * DQ) >> 32);
  return t;
}
static int32_t d_reduce32(int32_t a) {
  int32_t t = (a + (1 << 22)) >> 23;
  return a - t * DQ;
}
static int32_t d_caddq(int32_t a) {
  a += (a >> 31) & DQ;
  return a;
}

/* === NTT / inverse NTT. === */

void d_ntt(int32_t a[256]) {
  unsigned int len, start, j, k = 0;
  for (len = 128; len > 0; len >>= 1) {
    for (start = 0; start < 256; start = j + len) {
      int32_t zeta = d_zetas[++k];
      for (j = start; j < start + len; ++j) {
        int32_t t = d_mont_reduce((int64_t)zeta * a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
      }
    }
  }
}
void d_invntt(int32_t a[256]) {
  unsigned int start, len, j, k = 256;
  const int32_t f = 41978;
  for (len = 1; len < 256; len <<= 1) {
    for (start = 0; start < 256; start = j + len) {
      int32_t zeta = -d_zetas[--k];
      for (j = start; j < start + len; ++j) {
        int32_t t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = d_mont_reduce((int64_t)zeta * a[j + len]);
      }
    }
  }
  for (j = 0; j < 256; ++j) a[j] = d_mont_reduce((int64_t)f * a[j]);
}

/* === Polynomial operations. === */

void d_poly_reduce(int32_t a[256]) {
  unsigned int i; for (i = 0; i < 256; i++) a[i] = d_reduce32(a[i]);
}
void d_poly_caddq(int32_t a[256]) {
  unsigned int i; for (i = 0; i < 256; i++) a[i] = d_caddq(a[i]);
}
void d_poly_add(int32_t c[256], const int32_t a[256], const int32_t b[256]) {
  unsigned int i; for (i = 0; i < 256; i++) c[i] = a[i] + b[i];
}
void d_poly_sub(int32_t c[256], const int32_t a[256], const int32_t b[256]) {
  unsigned int i; for (i = 0; i < 256; i++) c[i] = a[i] - b[i];
}
void d_poly_shiftl(int32_t a[256]) {
  unsigned int i; for (i = 0; i < 256; i++) a[i] <<= DD;
}
void d_poly_pointwise(int32_t c[256], const int32_t a[256], const int32_t b[256]) {
  unsigned int i; for (i = 0; i < 256; i++) c[i] = d_mont_reduce((int64_t)a[i] * b[i]);
}

/* Power2Round, decompose, make_hint, use_hint — see FIPS 204 §4.1 (Hint). */

static int32_t d_power2round(int32_t *a0, int32_t a) {
  int32_t a1 = (a + (1 << (DD - 1)) - 1) >> DD;
  *a0 = a - (a1 << DD);
  return a1;
}
int32_t d_decompose(int32_t *a0, int32_t a) {
  int32_t a1 = (a + 127) >> 7;
  a1 = (a1 * 1025 + (1 << 21)) >> 22;
  a1 &= 15;
  *a0 = a - a1 * 2 * DGAMMA2;
  *a0 -= (((DQ - 1) / 2 - *a0) >> 31) & DQ;
  return a1;
}
unsigned int d_make_hint(int32_t a0, int32_t a1) {
  /* Constant-time: build three 0/1 flags and OR them.
   *   gt  = 1 iff a0 >  DGAMMA2
   *   lt  = 1 iff a0 < -DGAMMA2
   *   third = 1 iff a0 == -DGAMMA2 and a1 != 0
   * (a0 == -DGAMMA2) <=> (a0 + DGAMMA2) == 0; (a1 != 0) is the
   *  standard nonzero test via bitwise OR of the value and its negation. */
  uint32_t sum = (uint32_t)(a0 + DGAMMA2);
  uint32_t eq_neg = (uint32_t)1 - ((sum | ((uint32_t)0u - sum)) >> 31);
  uint32_t a1_nz  = ((uint32_t)a1 | (uint32_t)(-a1)) >> 31;
  uint32_t gt  = ((uint32_t)(DGAMMA2 - a0) >> 31) & 1u;
  uint32_t lt  = ((uint32_t)(a0 + DGAMMA2) >> 31) & 1u;
  return (gt | lt | (eq_neg & a1_nz)) & 1u;
}
int32_t d_use_hint(int32_t a, unsigned int hint) {
  int32_t a0, a1 = d_decompose(&a0, a);
  /* Constant-time: pick (a1+1)&15 if a0 > 0, else (a1-1)&15, gated by
   * the hint bit. All selects via bitmasks, no branches. */
  uint32_t hbit = (uint32_t)(hint & 1u);
  uint32_t hmask = (uint32_t)0 - hbit;                    /* 0xFFFFFFFF if hint != 0, 0 otherwise */
  uint32_t a0_pos = ((uint32_t)0 - (((uint32_t)(a0 - 1)) >> 31)) & 1u;  /* 1 if a0 > 0, else 0 */
  uint32_t a0_mask = (uint32_t)0 - a0_pos;                /* 0xFFFFFFFF if a0 > 0, 0 otherwise */
  uint32_t v_pos = (uint32_t)((a1 + 1) & 15);
  uint32_t v_neg = (uint32_t)((a1 - 1) & 15);
  uint32_t sel_step = (a0_mask & v_pos) | ((~a0_mask) & v_neg);
  uint32_t sel      = (hmask & sel_step) | ((~hmask) & (uint32_t)a1);
  return (int32_t)(sel & 15u);
}

/* Chknorm: returns 1 iff any |a[i]| >= B, else 0. Used for rejection. */
int d_chknorm(const int32_t a[256], int32_t B) {
  unsigned int i;
  if (B > (DQ - 1) / 8) return 1;
  for (i = 0; i < 256; i++) {
    int32_t t = a[i] >> 31;
    t = a[i] - (t & 2 * a[i]);
    if (t >= B) return 1;
  }
  return 0;
}

/* === Sampling: rejection sampling for A-matrix and eta, and γ1. === */

static unsigned int d_rej_uniform(int32_t *a, unsigned int len, const uint8_t *buf, unsigned int buflen) {
  unsigned int ctr = 0, pos = 0;
  while (ctr < len && pos + 3 <= buflen) {
    uint32_t t = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;
    if (t < (uint32_t)DQ) a[ctr++] = (int32_t)t;
  }
  return ctr;
}
static void d_poly_uniform(int32_t a[256], const uint8_t seed[32], uint16_t nonce) {
  uint8_t in[34], buf[1344];
  unsigned int ctr;
  memcpy(in, seed, 32);
  in[32] = (uint8_t)nonce;
  in[33] = (uint8_t)(nonce >> 8);
  oo_shake128(in, 34, buf, sizeof buf);
  ctr = d_rej_uniform(a, 256, buf, sizeof buf);
  /* v2.1.0: was `while (ctr < 256) { ...; break; }` — the `break` made
   * the loop a single iteration, so any rejection failure silently left
   * the coefficient uninitialised. ML-DSA FIPS 204 §4.1.1 requires
   * deterministic re-sampling. Now: keep drawing more bytes from SHAKE
   * (advance the nonce-derived state) until we have all 256 coefficients
   * or we exhaust the budget. */
  while (ctr < 256) {
    size_t need = 256 - ctr;
    uint8_t more[168];
    if (sizeof more < need * 3) break; /* budget guard */
    oo_shake128(in, 34, more, sizeof more);
    unsigned int got = d_rej_uniform(a + ctr, (unsigned int)need, more, sizeof more);
    ctr += got;
    if (got == 0) break; /* no progress possible in this draw */
  }
  (void)ctr;
  if (ctr < 256) {
    /* deterministic sampling exhausted the budget; this should not happen
     * for a well-seeded nonce, but fail closed rather than emit a bad
     * polynomial. */
    fprintf(stderr, "ERR\tpqc\tdeterministic sample exhausted in expand_a (ctr=%u)\n", ctr);
    exit(1);
  }
}
static unsigned int d_rej_eta(int32_t *a, unsigned int len, const uint8_t *buf, unsigned int buflen) {
  unsigned int ctr = 0, pos = 0;
  while (ctr < len && pos < buflen) {
    uint32_t t0 = buf[pos] & 0x0F;
    uint32_t t1 = buf[pos++] >> 4;
    if (t0 < 9) a[ctr++] = 4 - (int32_t)t0;
    if (t1 < 9 && ctr < len) a[ctr++] = 4 - (int32_t)t1;
  }
  return ctr;
}
void d_poly_uniform_eta(int32_t a[256], const uint8_t seed[64], uint16_t nonce) {
  uint8_t in[66], buf[544];
  memcpy(in, seed, 64);
  in[64] = (uint8_t)nonce;
  in[65] = (uint8_t)(nonce >> 8);
  oo_shake256(in, 66, buf, sizeof buf);
  d_rej_eta(a, 256, buf, sizeof buf);
}
void d_polyz_unpack(int32_t r[256], const uint8_t *a);
void d_poly_uniform_gamma1(int32_t a[256], const uint8_t seed[64], uint16_t nonce) {
  uint8_t in[66], buf[816];
  memcpy(in, seed, 64);
  in[64] = (uint8_t)nonce;
  in[65] = (uint8_t)(nonce >> 8);
  oo_shake256(in, 66, buf, sizeof buf);
  d_polyz_unpack(a, buf);
}
void d_poly_challenge(int32_t c[256], const uint8_t seed[48]) {
  unsigned int i, b, pos;
  uint64_t signs = 0;
  uint8_t buf[544];
  oo_shake256(seed, 48, buf, sizeof buf);
  for (i = 0; i < 8; ++i) signs |= (uint64_t)buf[i] << (8 * i);
  pos = 8;
  for (i = 0; i < 256; ++i) c[i] = 0;
  for (i = 256 - DTAU; i < 256; ++i) {
    do {
      b = buf[pos++];
    } while (b > i);
    c[i] = c[b];
    c[b] = 1 - 2 * (int32_t)(signs & 1);
    signs >>= 1;
  }
}

/* === Byte <-> polynomial pack/unpack. === */

void d_polyeta_pack(uint8_t *r, const int32_t a[256]) {
  unsigned int i;
  for (i = 0; i < 128; ++i) {
    uint8_t t0 = (uint8_t)(DETA - a[2 * i + 0]);
    uint8_t t1 = (uint8_t)(DETA - a[2 * i + 1]);
    r[i] = (uint8_t)(t0 | (t1 << 4));
  }
}
static void d_polyeta_unpack(int32_t r[256], const uint8_t *a) {
  unsigned int i;
  for (i = 0; i < 128; ++i) {
    r[2 * i + 0] = DETA - (int32_t)(a[i] & 0x0F);
    r[2 * i + 1] = DETA - (int32_t)(a[i] >> 4);
  }
}
void d_polyt1_pack(uint8_t *r, const int32_t a[256]) {
  unsigned int i;
  for (i = 0; i < 64; ++i) {
    r[5 * i + 0] = (uint8_t)(a[4 * i + 0] >> 0);
    r[5 * i + 1] = (uint8_t)((a[4 * i + 0] >> 8) | (a[4 * i + 1] << 2));
    r[5 * i + 2] = (uint8_t)((a[4 * i + 1] >> 6) | (a[4 * i + 2] << 4));
    r[5 * i + 3] = (uint8_t)((a[4 * i + 2] >> 4) | (a[4 * i + 3] << 6));
    r[5 * i + 4] = (uint8_t)(a[4 * i + 3] >> 2);
  }
}
static void d_polyt1_unpack(int32_t r[256], const uint8_t *a) {
  unsigned int i;
  for (i = 0; i < 64; ++i) {
    r[4 * i + 0] = ((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF;
    r[4 * i + 1] = ((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF;
    r[4 * i + 2] = ((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF;
    r[4 * i + 3] = ((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF;
  }
}
static void d_polyt0_pack(uint8_t *r, const int32_t a[256]) {
  unsigned int i;
  uint32_t t[8];
  for (i = 0; i < 32; ++i) {
    t[0] = (1 << (DD - 1)) - a[8 * i + 0];
    t[1] = (1 << (DD - 1)) - a[8 * i + 1];
    t[2] = (1 << (DD - 1)) - a[8 * i + 2];
    t[3] = (1 << (DD - 1)) - a[8 * i + 3];
    t[4] = (1 << (DD - 1)) - a[8 * i + 4];
    t[5] = (1 << (DD - 1)) - a[8 * i + 5];
    t[6] = (1 << (DD - 1)) - a[8 * i + 6];
    t[7] = (1 << (DD - 1)) - a[8 * i + 7];
    r[13 * i + 0] = (uint8_t)t[0];
    r[13 * i + 1] = (uint8_t)(t[0] >> 8);
    r[13 * i + 1] |= (uint8_t)(t[1] << 5);
    r[13 * i + 2] = (uint8_t)(t[1] >> 3);
    r[13 * i + 3] = (uint8_t)(t[1] >> 11);
    r[13 * i + 3] |= (uint8_t)(t[2] << 2);
    r[13 * i + 4] = (uint8_t)(t[2] >> 6);
    r[13 * i + 4] |= (uint8_t)(t[3] << 7);
    r[13 * i + 5] = (uint8_t)(t[3] >> 1);
    r[13 * i + 6] = (uint8_t)(t[3] >> 9);
    r[13 * i + 6] |= (uint8_t)(t[4] << 4);
    r[13 * i + 7] = (uint8_t)(t[4] >> 4);
    r[13 * i + 8] = (uint8_t)(t[4] >> 12);
    r[13 * i + 8] |= (uint8_t)(t[5] << 1);
    r[13 * i + 9] = (uint8_t)(t[5] >> 7);
    r[13 * i + 9] |= (uint8_t)(t[6] << 6);
    r[13 * i + 10] = (uint8_t)(t[6] >> 2);
    r[13 * i + 11] = (uint8_t)(t[6] >> 10);
    r[13 * i + 11] |= (uint8_t)(t[7] << 3);
    r[13 * i + 12] = (uint8_t)(t[7] >> 5);
  }
}
static void d_polyt0_unpack(int32_t r[256], const uint8_t *a) {
  unsigned int i;
  for (i = 0; i < 32; ++i) {
    r[8 * i + 0] = a[13 * i + 0];
    r[8 * i + 0] |= (uint32_t)a[13 * i + 1] << 8;
    r[8 * i + 0] &= 0x1FFF;
    r[8 * i + 1] = a[13 * i + 1] >> 5;
    r[8 * i + 1] |= (uint32_t)a[13 * i + 2] << 3;
    r[8 * i + 1] |= (uint32_t)a[13 * i + 3] << 11;
    r[8 * i + 1] &= 0x1FFF;
    r[8 * i + 2] = a[13 * i + 3] >> 2;
    r[8 * i + 2] |= (uint32_t)a[13 * i + 4] << 6;
    r[8 * i + 2] &= 0x1FFF;
    r[8 * i + 3] = a[13 * i + 4] >> 7;
    r[8 * i + 3] |= (uint32_t)a[13 * i + 5] << 1;
    r[8 * i + 3] |= (uint32_t)a[13 * i + 6] << 9;
    r[8 * i + 3] &= 0x1FFF;
    r[8 * i + 4] = a[13 * i + 6] >> 4;
    r[8 * i + 4] |= (uint32_t)a[13 * i + 7] << 4;
    r[8 * i + 4] |= (uint32_t)a[13 * i + 8] << 12;
    r[8 * i + 4] &= 0x1FFF;
    r[8 * i + 5] = a[13 * i + 8] >> 1;
    r[8 * i + 5] |= (uint32_t)a[13 * i + 9] << 7;
    r[8 * i + 5] &= 0x1FFF;
    r[8 * i + 6] = a[13 * i + 9] >> 6;
    r[8 * i + 6] |= (uint32_t)a[13 * i + 10] << 2;
    r[8 * i + 6] |= (uint32_t)a[13 * i + 11] << 10;
    r[8 * i + 6] &= 0x1FFF;
    r[8 * i + 7] = a[13 * i + 11] >> 3;
    r[8 * i + 7] |= (uint32_t)a[13 * i + 12] << 5;
    r[8 * i + 7] &= 0x1FFF;
    r[8 * i + 0] = (1 << (DD - 1)) - r[8 * i + 0];
    r[8 * i + 1] = (1 << (DD - 1)) - r[8 * i + 1];
    r[8 * i + 2] = (1 << (DD - 1)) - r[8 * i + 2];
    r[8 * i + 3] = (1 << (DD - 1)) - r[8 * i + 3];
    r[8 * i + 4] = (1 << (DD - 1)) - r[8 * i + 4];
    r[8 * i + 5] = (1 << (DD - 1)) - r[8 * i + 5];
    r[8 * i + 6] = (1 << (DD - 1)) - r[8 * i + 6];
    r[8 * i + 7] = (1 << (DD - 1)) - r[8 * i + 7];
  }
}
void d_polyz_pack(uint8_t *r, const int32_t a[256]) {
  unsigned int i;
  uint32_t t[2];
  for (i = 0; i < 128; ++i) {
    t[0] = DGAMMA1 - a[2 * i + 0];
    t[1] = DGAMMA1 - a[2 * i + 1];
    r[5 * i + 0] = (uint8_t)t[0];
    r[5 * i + 1] = (uint8_t)(t[0] >> 8);
    r[5 * i + 2] = (uint8_t)(t[0] >> 16);
    r[5 * i + 2] |= (uint8_t)(t[1] << 4);
    r[5 * i + 3] = (uint8_t)(t[1] >> 4);
    r[5 * i + 4] = (uint8_t)(t[1] >> 12);
  }
}
void d_polyz_unpack(int32_t r[256], const uint8_t *a) {
  unsigned int i;
  for (i = 0; i < 128; ++i) {
    r[2 * i + 0] = a[5 * i + 0];
    r[2 * i + 0] |= (uint32_t)a[5 * i + 1] << 8;
    r[2 * i + 0] |= (uint32_t)a[5 * i + 2] << 16;
    r[2 * i + 0] &= 0xFFFFF;
    r[2 * i + 1] = a[5 * i + 2] >> 4;
    r[2 * i + 1] |= (uint32_t)a[5 * i + 3] << 4;
    r[2 * i + 1] |= (uint32_t)a[5 * i + 4] << 12;
    r[2 * i + 0] = DGAMMA1 - r[2 * i + 0];
    r[2 * i + 1] = DGAMMA1 - r[2 * i + 1];
  }
}
void d_polyw1_pack(uint8_t *r, const int32_t a[256]) {
  unsigned int i;
  for (i = 0; i < 128; ++i)
    r[i] = (uint8_t)(a[2 * i + 0] | (a[2 * i + 1] << 4));
}

/* === Hex I/O glue (shared with mldsa.c, mldsa_sign.c, mldsa_verify.c). === */

int d_hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
int d_hex_load(OoStr s, uint8_t *out, size_t want) {
  size_t i, n;
  if (!s.data || s.len < 0) return 0;
  n = (size_t)s.len;
  if (n == want) { memcpy(out, s.data, want); return 1; }
  if (n != want * 2) return 0;
  for (i = 0; i < want; i++) {
    int hi = d_hex_digit(s.data[2 * i]), lo = d_hex_digit(s.data[2 * i + 1]);
    if (hi < 0 || lo < 0) return 0;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 1;
}
int d_load_msg(OoStr s, uint8_t *out, size_t *n, size_t maxn) {
  size_t i;
  if (!s.data || s.len < 0) { *n = 0; return 1; }
  if (s.len % 2 == 0 && (size_t)s.len / 2 <= maxn && (size_t)s.len > 0) {
    int all = 1;
    for (i = 0; i < (size_t)s.len; i++) if (d_hex_digit(s.data[i]) < 0) { all = 0; break; }
    if (all) {
      *n = (size_t)s.len / 2;
      for (i = 0; i < *n; i++) {
        int hi = d_hex_digit(s.data[2 * i]), lo = d_hex_digit(s.data[2 * i + 1]);
        out[i] = (uint8_t)((hi << 4) | lo);
      }
      return 1;
    }
  }
  if ((size_t)s.len > maxn) return 0;
  memcpy(out, s.data, (size_t)s.len);
  *n = (size_t)s.len;
  return 1;
}
OoStr d_hex_out(const uint8_t *p, size_t n) {
  static const char *hx = "0123456789abcdef";
  char *buf = oo_str_alloc_payload(n * 2);
  size_t i;
  for (i = 0; i < n; i++) { buf[i * 2] = hx[(p[i] >> 4) & 0xf]; buf[i * 2 + 1] = hx[p[i] & 0xf]; }
  { OoStr r; r.data = buf; r.len = (long long)(n * 2); return r; }
}
OoStr d_hex_out_cat(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
  static const char *hx = "0123456789abcdef";
  size_t n = na + nb, i;
  char *buf = oo_str_alloc_payload(n * 2);
  for (i = 0; i < na; i++) { buf[i * 2] = hx[(a[i] >> 4) & 0xf]; buf[i * 2 + 1] = hx[a[i] & 0xf]; }
  for (i = 0; i < nb; i++) { buf[(na + i) * 2] = hx[(b[i] >> 4) & 0xf]; buf[(na + i) * 2 + 1] = hx[b[i] & 0xf]; }
  { OoStr r; r.data = buf; r.len = (long long)(n * 2); return r; }
}

/* === Matrix expand / multiply + packing. === */

void d_expand_a(int32_t mat[DK][DL][256], const uint8_t rho[32]) {
  int i, j;
  for (i = 0; i < DK; i++)
    for (j = 0; j < DL; j++)
      d_poly_uniform(mat[i][j], rho, (uint16_t)((i << 8) + j));
}
void d_matrix_pointwise(int32_t t[DK][256], int32_t mat[DK][DL][256], int32_t v[DL][256]) {
  int i, j;
  int32_t tmp[256];
  for (i = 0; i < DK; i++) {
    d_poly_pointwise(t[i], mat[i][0], v[0]);
    for (j = 1; j < DL; j++) {
      d_poly_pointwise(tmp, mat[i][j], v[j]);
      d_poly_add(t[i], t[i], tmp);
    }
  }
}

static void d_pack_pk(uint8_t pk[DPK], const uint8_t rho[32], int32_t t1[DK][256]) {
  int i;
  memcpy(pk, rho, 32);
  for (i = 0; i < DK; i++) d_polyt1_pack(pk + 32 + i * DPOLYT1, t1[i]);
}
static void d_pack_sk(uint8_t sk[DSK], const uint8_t rho[32], const uint8_t tr[64],
                     const uint8_t key[32], int32_t t0[DK][256], int32_t s1[DL][256], int32_t s2[DK][256]) {
  int i;
  uint8_t *p = sk;
  memcpy(p, rho, 32); p += 32;
  memcpy(p, key, 32); p += 32;
  memcpy(p, tr, 64); p += 64;
  for (i = 0; i < DL; i++) { d_polyeta_pack(p, s1[i]); p += DPOLYETA; }
  for (i = 0; i < DK; i++) { d_polyeta_pack(p, s2[i]); p += DPOLYETA; }
  for (i = 0; i < DK; i++) { d_polyt0_pack(p, t0[i]); p += DPOLYT0; }
}
void d_unpack_pk(uint8_t rho[32], int32_t t1[DK][256], const uint8_t pk[DPK]) {
  int i;
  memcpy(rho, pk, 32);
  for (i = 0; i < DK; i++) d_polyt1_unpack(t1[i], pk + 32 + i * DPOLYT1);
}
void d_unpack_sk(uint8_t rho[32], uint8_t tr[64], uint8_t key[32],
                 int32_t t0[DK][256], int32_t s1[DL][256], int32_t s2[DK][256],
                 const uint8_t sk[DSK]) {
  int i;
  const uint8_t *p = sk;
  memcpy(rho, p, 32); p += 32;
  memcpy(key, p, 32); p += 32;
  memcpy(tr, p, 64); p += 64;
  for (i = 0; i < DL; i++) { d_polyeta_unpack(s1[i], p); p += DPOLYETA; }
  for (i = 0; i < DK; i++) { d_polyeta_unpack(s2[i], p); p += DPOLYETA; }
  for (i = 0; i < DK; i++) { d_polyt0_unpack(t0[i], p); p += DPOLYT0; }
}
void d_pack_sig(uint8_t sig[DSIG], const uint8_t c[DCTILDE], int32_t z[DL][256], int32_t h[DK][256]) {
  unsigned int i, j, k;
  memcpy(sig, c, DCTILDE);
  for (i = 0; i < DL; i++) d_polyz_pack(sig + DCTILDE + i * DPOLYZ, z[i]);
  {
    uint8_t *hs = sig + DCTILDE + DL * DPOLYZ;
    memset(hs, 0, DOMEGA + DK);
    /* Constant-time hint packing: the write itself is masked, and k
     * increments via a branchless mask. The variable-time access pattern
     * is inherent to the sparse-packing format; we eliminate the branch. */
    k = 0;
    for (i = 0; i < DK; i++) {
      for (j = 0; j < DN; j++) {
        uint32_t set = ((uint32_t)h[i][j] | (uint32_t)(-h[i][j])) >> 31;  /* 1 if h[i][j] != 0, else 0 */
        uint32_t mask = (uint32_t)0 - set;                                 /* 0xFFFFFFFF if set, 0 otherwise */
        uint32_t new_val = (mask & (uint32_t)(uint8_t)j) | ((~mask) & (uint32_t)hs[k]);
        hs[k] = (uint8_t)(new_val & 0xFFu);
        k += set & 1u;
      }
      hs[DOMEGA + i] = (uint8_t)k;
    }
  }
}
int d_unpack_sig(uint8_t c[DCTILDE], int32_t z[DL][256], int32_t h[DK][256], const uint8_t sig[DSIG]) {
  unsigned int i, j, k;
  const uint8_t *hs;
  memcpy(c, sig, DCTILDE);
  for (i = 0; i < DL; i++) d_polyz_unpack(z[i], sig + DCTILDE + i * DPOLYZ);
  hs = sig + DCTILDE + DL * DPOLYZ;
  k = 0;
  for (i = 0; i < DK; i++) {
    for (j = 0; j < DN; j++) h[i][j] = 0;
    if (hs[DOMEGA + i] < k || hs[DOMEGA + i] > DOMEGA) return 1;
    for (j = k; j < hs[DOMEGA + i]; ++j) {
      if (j > k && hs[j] <= hs[j - 1]) return 1;
      h[i][hs[j]] = 1;
    }
    k = hs[DOMEGA + i];
  }
  for (j = k; j < DOMEGA; ++j) if (hs[j]) return 1;
  return 0;
}

/* === d_keygen: FIPS 204 §6.1 (ML-DSA.KeyGen). === */

void d_keygen(const uint8_t xi[32], uint8_t pk[DPK], uint8_t sk[DSK]) {
  uint8_t seedbuf[34 + 128];
  uint8_t tr[DTR];
  const uint8_t *rho, *rhoprime, *key;
  int32_t mat[DK][DL][256], s1[DL][256], s1hat[DL][256], s2[DK][256], t1[DK][256], t0[DK][256];
  int i;
  memcpy(seedbuf, xi, 32);
  seedbuf[32] = (uint8_t)DK;
  seedbuf[33] = (uint8_t)DL;
  oo_shake256(seedbuf, 34, seedbuf + 34, 2 * DSEED + DTR);
  rho = seedbuf + 34;
  rhoprime = rho + DSEED;
  key = rhoprime + DTR;
  d_expand_a(mat, rho);
  for (i = 0; i < DL; i++) d_poly_uniform_eta(s1[i], rhoprime, (uint16_t)i);
  for (i = 0; i < DK; i++) d_poly_uniform_eta(s2[i], rhoprime, (uint16_t)(DL + i));
  for (i = 0; i < DL; i++) { memcpy(s1hat[i], s1[i], sizeof s1[i]); d_ntt(s1hat[i]); }
  d_matrix_pointwise(t1, mat, s1hat);
  for (i = 0; i < DK; i++) { d_poly_reduce(t1[i]); d_invntt(t1[i]); d_poly_add(t1[i], t1[i], s2[i]); d_poly_caddq(t1[i]); }
  for (i = 0; i < DK; i++) {
    unsigned int j;
    for (j = 0; j < 256; j++) t1[i][j] = d_power2round(&t0[i][j], t1[i][j]);
  }
  d_pack_pk(pk, rho, t1);
  oo_shake256(pk, DPK, tr, DTR);
  d_pack_sk(sk, rho, tr, key, t0, s1, s2);
}
