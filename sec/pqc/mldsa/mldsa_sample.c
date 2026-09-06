#include "mldsa_internal.h"
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
