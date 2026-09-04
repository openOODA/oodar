/* AES-128-GCM (NIST SP 800-38D) seal/open.
 *
 * v2.3.0 file split: extracted from the monolithic sec/crypto/aead.c.
 * Shared hex/binary loaders and concatenation live in aead/aead.c
 * (must be #included first in the umbrella). The seal/open entry points
 * are referenced by sec/crypto/seal.c (the cap-gated public surface). */
#include "../../../oodar.h"
#include "../crypto_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
