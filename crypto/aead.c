/* AES-128-GCM (NIST SP 800-38D) and ChaCha20-Poly1305 (RFC 8439). */
#include "../oodar.h"
#include <stdint.h>

static const uint8_t k_aes_sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t k_aes_rcon[11] = {0,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t aead_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

static void aead_aes_expand(const uint8_t key[16], uint8_t rk[176]) {
  int i;
  memcpy(rk, key, 16);
  for (i = 4; i < 44; i++) {
    uint8_t t[4];
    memcpy(t, rk + (i - 1) * 4, 4);
    if ((i % 4) == 0) {
      uint8_t tmp = t[0];
      t[0] = (uint8_t)(k_aes_sbox[t[1]] ^ k_aes_rcon[i / 4]);
      t[1] = k_aes_sbox[t[2]];
      t[2] = k_aes_sbox[t[3]];
      t[3] = k_aes_sbox[tmp];
    }
    rk[i * 4] = (uint8_t)(rk[(i - 4) * 4] ^ t[0]);
    rk[i * 4 + 1] = (uint8_t)(rk[(i - 4) * 4 + 1] ^ t[1]);
    rk[i * 4 + 2] = (uint8_t)(rk[(i - 4) * 4 + 2] ^ t[2]);
    rk[i * 4 + 3] = (uint8_t)(rk[(i - 4) * 4 + 3] ^ t[3]);
  }
}

static void aead_aes_encrypt(const uint8_t in[16], const uint8_t rk[176], uint8_t out[16]) {
  uint8_t s[16];
  int round, i;
  memcpy(s, in, 16);
  for (i = 0; i < 16; i++) s[i] ^= rk[i];
  for (round = 1; round <= 10; round++) {
    uint8_t t[16];
    for (i = 0; i < 16; i++) t[i] = k_aes_sbox[s[i]];
    s[0]=t[0]; s[1]=t[5]; s[2]=t[10]; s[3]=t[15];
    s[4]=t[4]; s[5]=t[9]; s[6]=t[14]; s[7]=t[3];
    s[8]=t[8]; s[9]=t[13]; s[10]=t[2]; s[11]=t[7];
    s[12]=t[12]; s[13]=t[1]; s[14]=t[6]; s[15]=t[11];
    if (round < 10) {
      for (i = 0; i < 16; i += 4) {
        uint8_t a=s[i], b=s[i+1], c=s[i+2], d=s[i+3];
        s[i]   = (uint8_t)(aead_xtime(a) ^ aead_xtime(b) ^ b ^ c ^ d);
        s[i+1] = (uint8_t)(a ^ aead_xtime(b) ^ aead_xtime(c) ^ c ^ d);
        s[i+2] = (uint8_t)(a ^ b ^ aead_xtime(c) ^ aead_xtime(d) ^ d);
        s[i+3] = (uint8_t)(aead_xtime(a) ^ a ^ b ^ c ^ aead_xtime(d));
      }
    }
    for (i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
  }
  memcpy(out, s, 16);
}

static void gcm_inc32(uint8_t b[16]) {
  uint32_t n = ((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16) | ((uint32_t)b[14] << 8) | b[15];
  n++;
  b[12] = (uint8_t)(n >> 24); b[13] = (uint8_t)(n >> 16); b[14] = (uint8_t)(n >> 8); b[15] = (uint8_t)n;
}

static void gcm_xor16(uint8_t a[16], const uint8_t b[16]) {
  int i; for (i = 0; i < 16; i++) a[i] ^= b[i];
}

static void gcm_gf_mult(const uint8_t x[16], const uint8_t y[16], uint8_t z[16]) {
  uint8_t v[16], r[16];
  int i, j, k;
  memcpy(v, y, 16);
  memset(r, 0, 16);
  for (i = 0; i < 16; i++) {
    for (j = 0; j < 8; j++) {
      /* Constant-time: mask = 0xFF if x[i] bit (7-j) is set, else 0. */
      uint8_t bit = (uint8_t)((x[i] >> (7 - j)) & 1u);
      uint8_t mask = (uint8_t)(-(int8_t)bit);
      for (k = 0; k < 16; k++) r[k] ^= (uint8_t)(v[k] & mask);
      {
        uint8_t lsb = (uint8_t)(v[15] & 1);
        for (k = 15; k > 0; k--) v[k] = (uint8_t)((v[k] >> 1) | (v[k - 1] << 7));
        v[0] >>= 1;
        /* Constant-time: only XOR 0xe1 when lsb is set. */
        v[0] ^= (uint8_t)(0xe1u & (uint8_t)(-(int8_t)lsb));
      }
    }
  }
  memcpy(z, r, 16);
}

static void gcm_ghash(const uint8_t h[16], const uint8_t *aad, size_t aad_n,
                      const uint8_t *ct, size_t ct_n, uint8_t out[16]) {
  uint8_t y[16], blk[16];
  size_t off;
  memset(y, 0, 16);
  for (off = 0; off < aad_n; off += 16) {
    size_t n = aad_n - off; if (n > 16) n = 16;
    memset(blk, 0, 16); memcpy(blk, aad + off, n);
    gcm_xor16(y, blk); gcm_gf_mult(y, h, y);
  }
  for (off = 0; off < ct_n; off += 16) {
    size_t n = ct_n - off; if (n > 16) n = 16;
    memset(blk, 0, 16); memcpy(blk, ct + off, n);
    gcm_xor16(y, blk); gcm_gf_mult(y, h, y);
  }
  memset(blk, 0, 16);
  {
    uint64_t ab = (uint64_t)aad_n * 8, cb = (uint64_t)ct_n * 8;
    int i;
    for (i = 0; i < 8; i++) blk[7 - i] = (uint8_t)(ab >> (8 * i));
    for (i = 0; i < 8; i++) blk[15 - i] = (uint8_t)(cb >> (8 * i));
  }
  gcm_xor16(y, blk); gcm_gf_mult(y, h, y);
  memcpy(out, y, 16);
}

static void gcm_gctr(const uint8_t rk[176], uint8_t icb[16], const uint8_t *x, size_t n, uint8_t *out) {
  uint8_t cb[16], ks[16];
  size_t off = 0;
  memcpy(cb, icb, 16);
  while (off < n) {
    size_t i, left = n - off; if (left > 16) left = 16;
    aead_aes_encrypt(cb, rk, ks);
    for (i = 0; i < left; i++) out[off + i] = (uint8_t)(x[off + i] ^ ks[i]);
    gcm_inc32(cb);
    off += left;
  }
}

static int aead_hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static int aead_all_hex(OoStr s) {
  size_t i;
  if (!s.data || s.len < 2 || (s.len % 2) != 0) return 0;
  for (i = 0; i < (size_t)s.len; i++) if (aead_hex_digit(s.data[i]) < 0) return 0;
  return 1;
}
static int aead_fill(OoStr s, uint8_t *out, size_t want) {
  size_t i;
  if (s.data && s.len == (long long)want) { memcpy(out, s.data, want); return 1; }
  if (s.data && s.len == (long long)want * 2) {
    for (i = 0; i < want; i++) {
      int hi = aead_hex_digit(s.data[2 * i]), lo = aead_hex_digit(s.data[2 * i + 1]);
      if (hi < 0 || lo < 0) return 0;
      out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
  }
  return 0;
}
static int aead_load(OoStr s, uint8_t **out, size_t *n, int *own) {
  *own = 0;
  if (s.len < 0) return 0;
  if (aead_all_hex(s)) {
    size_t i, m = (size_t)s.len / 2;
    uint8_t *b = (uint8_t *)malloc(m ? m : 1);
    if (!b) abort();
    for (i = 0; i < m; i++) {
      int hi = aead_hex_digit(s.data[2 * i]), lo = aead_hex_digit(s.data[2 * i + 1]);
      b[i] = (uint8_t)((hi << 4) | lo);
    }
    *out = b; *n = m; *own = 1; return 1;
  }
  *n = s.data && s.len > 0 ? (size_t)s.len : 0;
  *out = (uint8_t *)(*n ? s.data : "");
  return 1;
}

static OoStr aead_hex_cat(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
  static const char *hx = "0123456789abcdef";
  size_t n = na + nb, i;
  char *buf = oo_str_alloc_payload(n * 2);
  for (i = 0; i < na; i++) { buf[i * 2] = hx[(a[i] >> 4) & 0xf]; buf[i * 2 + 1] = hx[a[i] & 0xf]; }
  for (i = 0; i < nb; i++) { buf[(na + i) * 2] = hx[(b[i] >> 4) & 0xf]; buf[(na + i) * 2 + 1] = hx[b[i] & 0xf]; }
  { OoStr r; r.data = buf; r.len = (long long)(n * 2); return r; }
}

static OoStr aead_bin(const uint8_t *p, size_t n) {
  char *buf = oo_str_alloc_payload(n);
  if (n && p) memcpy(buf, p, n);
  { OoStr r; r.data = buf; r.len = (long long)n; return r; }
}

static void gcm_wipe_secrets(uint8_t kb[16], uint8_t nb[12], uint8_t rk[176],
                             uint8_t h[16], uint8_t j0[16], uint8_t s[16],
                             uint8_t tag[16], uint8_t z[16], uint8_t tb[16]) {
  crypto_secure_wipe(kb, 16);
  crypto_secure_wipe(nb, 12);
  crypto_secure_wipe(rk, 176);
  crypto_secure_wipe(h, 16);
  crypto_secure_wipe(j0, 16);
  crypto_secure_wipe(s, 16);
  crypto_secure_wipe(tag, 16);
  crypto_secure_wipe(z, 16);
  if (tb) crypto_secure_wipe(tb, 16);
}

OoStr crypto_aes_gcm_seal_internal(OoStr key, OoStr nonce, OoStr pt, OoStr aad) {
  uint8_t rk[176], h[16], j0[16], s[16], tag[16], z[16], kb[16], nb[12];
  uint8_t *p, *a, *ct;
  size_t pn, an;
  int op, oa;
  memset(kb, 0, 16); memset(nb, 0, 12); memset(rk, 0, sizeof rk);
  if (!aead_fill(key, kb, 16) || !aead_fill(nonce, nb, 12)) {
    gcm_wipe_secrets(kb, nb, rk, h, j0, s, tag, z, 0);
    return oo_str_lit("");
  }
  aead_load(pt, &p, &pn, &op); aead_load(aad, &a, &an, &oa);
  aead_aes_expand(kb, rk);
  memset(z, 0, 16); aead_aes_encrypt(z, rk, h);
  memcpy(j0, nb, 12); j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;
  ct = (uint8_t *)calloc(pn ? pn : 1, 1);
  if (!ct) abort();
  {
    uint8_t icb[16];
    memcpy(icb, j0, 16); gcm_inc32(icb);
    if (pn) gcm_gctr(rk, icb, p, pn, ct);
  }
  gcm_ghash(h, a, an, ct, pn, s);
  aead_aes_encrypt(j0, rk, tag);
  gcm_xor16(tag, s);
  {
    OoStr r = aead_hex_cat(ct, pn, tag, 16);
    free(ct);
    if (op) free(p);
    if (oa) free(a);
    gcm_wipe_secrets(kb, nb, rk, h, j0, s, tag, z, 0);
    return r;
  }
}

OoStr crypto_aes_gcm_open_internal(OoStr key, OoStr nonce, OoStr ct, OoStr tag, OoStr aad) {
  uint8_t rk[176], h[16], j0[16], s[16], expect[16], z[16], kb[16], nb[12], tb[16];
  uint8_t *c, *a, *pt;
  size_t cn, an;
  int oc, oa;
  memset(kb, 0, 16); memset(nb, 0, 12); memset(tb, 0, 16); memset(rk, 0, sizeof rk);
  if (!aead_fill(key, kb, 16) || !aead_fill(nonce, nb, 12) || !aead_fill(tag, tb, 16)) {
    gcm_wipe_secrets(kb, nb, rk, h, j0, s, expect, z, tb);
    return oo_str_lit("");
  }
  aead_load(ct, &c, &cn, &oc); aead_load(aad, &a, &an, &oa);
  aead_aes_expand(kb, rk);
  memset(z, 0, 16); aead_aes_encrypt(z, rk, h);
  memcpy(j0, nb, 12); j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;
  gcm_ghash(h, a, an, c, cn, s);
  aead_aes_encrypt(j0, rk, expect);
  gcm_xor16(expect, s);
  if (crypto_ct_cmp(expect, tb, 16) != 0) {
    if (oc) free(c); if (oa) free(a);
    gcm_wipe_secrets(kb, nb, rk, h, j0, s, expect, z, tb);
    return oo_str_lit("");
  }
  pt = (uint8_t *)calloc(cn ? cn : 1, 1);
  if (!pt) abort();
  {
    uint8_t icb[16];
    memcpy(icb, j0, 16); gcm_inc32(icb);
    if (cn) gcm_gctr(rk, icb, c, cn, pt);
  }
  {
    OoStr r = aead_bin(pt, cn);
    free(pt);
    if (oc) free(c); if (oa) free(a);
    gcm_wipe_secrets(kb, nb, rk, h, j0, s, expect, z, tb);
    return r;
  }
}

static uint32_t cc_rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static uint32_t cc_load32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void cc_store32(uint8_t *p, uint32_t x) {
  p[0]=(uint8_t)x; p[1]=(uint8_t)(x>>8); p[2]=(uint8_t)(x>>16); p[3]=(uint8_t)(x>>24);
}
static void cc_qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
  *a += *b; *d ^= *a; *d = cc_rotl(*d, 16);
  *c += *d; *b ^= *c; *b = cc_rotl(*b, 12);
  *a += *b; *d ^= *a; *d = cc_rotl(*d, 8);
  *c += *d; *b ^= *c; *b = cc_rotl(*b, 7);
}

static void chacha_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
  uint32_t x[16], orig[16];
  int i;
  x[0]=0x61707865; x[1]=0x3320646e; x[2]=0x79622d32; x[3]=0x6b206574;
  for (i = 0; i < 8; i++) x[4 + i] = cc_load32(key + 4 * i);
  x[12] = counter;
  x[13] = cc_load32(nonce); x[14] = cc_load32(nonce + 4); x[15] = cc_load32(nonce + 8);
  memcpy(orig, x, sizeof x);
  for (i = 0; i < 10; i++) {
    cc_qr(x+0,x+4,x+8,x+12); cc_qr(x+1,x+5,x+9,x+13);
    cc_qr(x+2,x+6,x+10,x+14); cc_qr(x+3,x+7,x+11,x+15);
    cc_qr(x+0,x+5,x+10,x+15); cc_qr(x+1,x+6,x+11,x+12);
    cc_qr(x+2,x+7,x+8,x+13); cc_qr(x+3,x+4,x+9,x+14);
  }
  for (i = 0; i < 16; i++) cc_store32(out + 4 * i, x[i] + orig[i]);
}

static void chacha_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                       const uint8_t *in, size_t n, uint8_t *out) {
  uint8_t blk[64];
  size_t off = 0;
  while (off < n) {
    size_t i, left = n - off; if (left > 64) left = 64;
    chacha_block(key, nonce, counter++, blk);
    for (i = 0; i < left; i++) out[off + i] = (uint8_t)(in[off + i] ^ blk[i]);
    off += left;
  }
}

static void poly1305_mac(const uint8_t key[32], const uint8_t *m, size_t n, uint8_t tag[16]) {
  uint32_t r0, r1, r2, r3, r4, s1, s2, s3, s4;
  uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
  uint32_t t0, t1, t2, t3;
  size_t off = 0;
  t0 = cc_load32(key); t1 = cc_load32(key + 4); t2 = cc_load32(key + 8); t3 = cc_load32(key + 12);
  r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
  r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
  r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
  r3 = t2 & 0x3f03fff; t3 >>= 8;
  r4 = t3 & 0x00fffff;
  s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;
  while (off < n) {
    uint64_t d0, d1, d2, d3, d4;
    uint8_t blk[16];
    size_t left = n - off; if (left > 16) left = 16;
    memset(blk, 0, 16); memcpy(blk, m + off, left);
    t0 = cc_load32(blk); t1 = cc_load32(blk + 4); t2 = cc_load32(blk + 8); t3 = cc_load32(blk + 12);
    h0 += t0 & 0x3ffffff;
    h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    h4 += (t3 >> 8) | (uint32_t)(1u << 24);
    d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
    d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
    d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
    d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
    d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;
    h0 = (uint32_t)(d0 & 0x3ffffff); d1 += d0 >> 26;
    h1 = (uint32_t)(d1 & 0x3ffffff); d2 += d1 >> 26;
    h2 = (uint32_t)(d2 & 0x3ffffff); d3 += d2 >> 26;
    h3 = (uint32_t)(d3 & 0x3ffffff); d4 += d3 >> 26;
    h4 = (uint32_t)(d4 & 0x3ffffff); h0 += (uint32_t)(d4 >> 26) * 5;
    h1 += h0 >> 26; h0 &= 0x3ffffff;
    off += left;
  }
  {
    uint64_t f; uint32_t g0,g1,g2,g3,g4,mask;
    h2 += h1 >> 26; h1 &= 0x3ffffff;
    h3 += h2 >> 26; h2 &= 0x3ffffff;
    h4 += h3 >> 26; h3 &= 0x3ffffff;
    h0 += (h4 >> 26) * 5; h4 &= 0x3ffffff;
    h1 += h0 >> 26; h0 &= 0x3ffffff;
    g0 = h0 + 5; g1 = h1 + (g0 >> 26); g0 &= 0x3ffffff;
    g2 = h2 + (g1 >> 26); g1 &= 0x3ffffff;
    g3 = h3 + (g2 >> 26); g2 &= 0x3ffffff;
    g4 = h4 + (g3 >> 26) - (1u << 26); g3 &= 0x3ffffff;
    mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;
    f = (uint64_t)h0 + cc_load32(key + 16); cc_store32(tag, (uint32_t)f);
    f = (uint64_t)h1 + cc_load32(key + 20) + (f >> 32); cc_store32(tag + 4, (uint32_t)f);
    f = (uint64_t)h2 + cc_load32(key + 24) + (f >> 32); cc_store32(tag + 8, (uint32_t)f);
    f = (uint64_t)h3 + cc_load32(key + 28) + (f >> 32); cc_store32(tag + 12, (uint32_t)f);
  }
}

static void poly_pad_mac(const uint8_t key[32], const uint8_t *aad, size_t an,
                         const uint8_t *ct, size_t cn, uint8_t tag[16]) {
  size_t aad_pad = (16 - (an % 16)) % 16;
  size_t ct_pad = (16 - (cn % 16)) % 16;
  size_t n = an + aad_pad + cn + ct_pad + 16;
  uint8_t *buf = (uint8_t *)calloc(n ? n : 1, 1);
  uint8_t lenblk[16];
  if (!buf) abort();
  memcpy(buf, aad, an);
  memcpy(buf + an + aad_pad, ct, cn);
  memset(lenblk, 0, 16);
  {
    uint64_t al = (uint64_t)an, cl = (uint64_t)cn;
    int i;
    for (i = 0; i < 8; i++) lenblk[i] = (uint8_t)(al >> (8 * i));
    for (i = 0; i < 8; i++) lenblk[8 + i] = (uint8_t)(cl >> (8 * i));
  }
  memcpy(buf + an + aad_pad + cn + ct_pad, lenblk, 16);
  poly1305_mac(key, buf, n, tag);
  free(buf);
}

static void cc_wipe_secrets(uint8_t kb[32], uint8_t nb[12], uint8_t otk[64], uint8_t tag[16], uint8_t tb[16]) {
  crypto_secure_wipe(kb, 32);
  crypto_secure_wipe(nb, 12);
  crypto_secure_wipe(otk, 64);
  crypto_secure_wipe(tag, 16);
  if (tb) crypto_secure_wipe(tb, 16);
}

OoStr crypto_chacha20poly1305_seal_internal(OoStr key, OoStr nonce, OoStr pt, OoStr aad) {
  uint8_t otk[64], *p, *a, *ct, tag[16], kb[32], nb[12];
  size_t pn, an;
  int op, oa;
  memset(kb, 0, 32); memset(nb, 0, 12); memset(otk, 0, 64);
  if (!aead_fill(key, kb, 32) || !aead_fill(nonce, nb, 12)) {
    cc_wipe_secrets(kb, nb, otk, tag, 0);
    return oo_str_lit("");
  }
  aead_load(pt, &p, &pn, &op); aead_load(aad, &a, &an, &oa);
  chacha_block(kb, nb, 0, otk);
  ct = (uint8_t *)calloc(pn ? pn : 1, 1);
  if (!ct) abort();
  if (pn) chacha_xor(kb, nb, 1, p, pn, ct);
  poly_pad_mac(otk, a, an, ct, pn, tag);
  {
    OoStr r = aead_hex_cat(ct, pn, tag, 16);
    free(ct);
    if (op) free(p); if (oa) free(a);
    cc_wipe_secrets(kb, nb, otk, tag, 0);
    return r;
  }
}

OoStr crypto_chacha20poly1305_open_internal(OoStr key, OoStr nonce, OoStr ct, OoStr tag, OoStr aad) {
  uint8_t otk[64], *c, *a, *pt, expect[16], kb[32], nb[12], tb[16];
  size_t cn, an;
  int oc, oa;
  memset(kb, 0, 32); memset(nb, 0, 12); memset(otk, 0, 64); memset(tb, 0, 16);
  if (!aead_fill(key, kb, 32) || !aead_fill(nonce, nb, 12) || !aead_fill(tag, tb, 16)) {
    cc_wipe_secrets(kb, nb, otk, expect, tb);
    return oo_str_lit("");
  }
  aead_load(ct, &c, &cn, &oc); aead_load(aad, &a, &an, &oa);
  chacha_block(kb, nb, 0, otk);
  poly_pad_mac(otk, a, an, c, cn, expect);
  if (crypto_ct_cmp(expect, tb, 16) != 0) {
    if (oc) free(c); if (oa) free(a);
    cc_wipe_secrets(kb, nb, otk, expect, tb);
    return oo_str_lit("");
  }
  pt = (uint8_t *)calloc(cn ? cn : 1, 1);
  if (!pt) abort();
  if (cn) chacha_xor(kb, nb, 1, c, cn, pt);
  {
    OoStr r = aead_bin(pt, cn);
    free(pt);
    if (oc) free(c); if (oa) free(a);
    cc_wipe_secrets(kb, nb, otk, expect, tb);
    return r;
  }
}
