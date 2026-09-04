/* ChaCha20-Poly1305 (RFC 8439) seal/open.
 *
 * v2.3.0 file split: extracted from the monolithic sec/crypto/aead.c.
 * Shared hex/binary loaders and concatenation live in aead/aead.c
 * (must be #included first in the umbrella). */
#include "../../../oodar.h"
#include "../crypto_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
    if (op) free(p);
    if (oa) free(a);
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
    if (oc) free(c);
    if (oa) free(a);
    cc_wipe_secrets(kb, nb, otk, expect, tb);
    return oo_str_lit("");
  }
  pt = (uint8_t *)calloc(cn ? cn : 1, 1);
  if (!pt) abort();
  if (cn) chacha_xor(kb, nb, 1, c, cn, pt);
  {
    OoStr r = aead_bin(pt, cn);
    free(pt);
    if (oc) free(c);
    if (oa) free(a);
    cc_wipe_secrets(kb, nb, otk, expect, tb);
    return r;
  }
}
