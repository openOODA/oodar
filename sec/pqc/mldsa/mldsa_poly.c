#include "mldsa_internal.h"
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
