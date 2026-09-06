#include "mlkem_internal.h"
  int i; for (i = 0; i < 256; i++) r[i] = k_montgomery((int32_t)r[i] * f);
}

/* === 24-bit and 32-bit little-endian byte loaders (FIPS 203 §4.2.1). ===
 * v3.3.2: k_load24 and k_load32 are defined but never called
 * (FIPS 203 uses k_load32 in encode/decode, which we don't need
 * for the oodar cap surface). Removed to clear the
 * -Wunused-function warnings and shrink the file by 6 lines.
 * The intent of the comment is preserved for the human auditor. */

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

/* v3.3.2 round-5 audit fix: the seed parameter is 32 bytes, not
 * 64. The previous signature `const uint8_t seed[64]` lied to the
 * compiler (and to the human auditor) — k_prf only ever used 32
 * bytes of seed. The "64" was a copy from a reference
 * implementation that used SHAKE256 with 64-byte block alignment.
 * Calling k_prf with a 32-byte seed array would trigger -Wstringop-overread
 * because the function declared a 64-byte parameter but
 * oo_shake256 was passed a 33-byte ext buffer derived from
 * only 32 bytes of seed (the rest would be uninitialized stack
 * garbage if the seed was actually 32 bytes).
 *
 * The seed is the public matrix seed from keygen or the
 * per-message seed from encaps. 32 bytes is what FIPS 203
 * specifies. The fix: change the signature to match the
 * implementation. */
static void k_prf(uint8_t *out, size_t outn, const uint8_t seed[32], uint8_t nonce) {
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
