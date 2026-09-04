/* FIPS 202 SHA3-256 and SHAKE128/SHAKE256. Product Keccak-f[1600]. */
#include "../../oodar.h"
#include <stdint.h>

static const uint64_t k_keccak_rc[24] = {
  0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
  0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
  0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
  0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
  0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};
static const int k_keccak_rot[24] = {
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
  27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};
static const int k_keccak_pil[24] = {
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
  15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static uint64_t k_rotl64(uint64_t x, int n) {
  return (x << n) | (x >> (64 - n));
}

static void keccak_f(uint64_t st[25]) {
  int round, i, j;
  uint64_t bc[5], t;
  for (round = 0; round < 24; round++) {
    for (i = 0; i < 5; i++)
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    for (i = 0; i < 5; i++) {
      t = bc[(i + 4) % 5] ^ k_rotl64(bc[(i + 1) % 5], 1);
      for (j = 0; j < 25; j += 5) st[j + i] ^= t;
    }
    t = st[1];
    for (i = 0; i < 24; i++) {
      j = k_keccak_pil[i];
      bc[0] = st[j];
      st[j] = k_rotl64(t, k_keccak_rot[i]);
      t = bc[0];
    }
    for (j = 0; j < 25; j += 5) {
      uint64_t a0 = st[j], a1 = st[j + 1], a2 = st[j + 2], a3 = st[j + 3], a4 = st[j + 4];
      st[j] = a0 ^ ((~a1) & a2);
      st[j + 1] = a1 ^ ((~a2) & a3);
      st[j + 2] = a2 ^ ((~a3) & a4);
      st[j + 3] = a3 ^ ((~a4) & a0);
      st[j + 4] = a4 ^ ((~a0) & a1);
    }
    st[0] ^= k_keccak_rc[round];
  }
}

static void keccak_absorb_squeeze(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen,
                                  size_t rate, uint8_t ds) {
  uint64_t st[25];
  size_t i, n;
  memset(st, 0, sizeof st);
  while (inlen >= rate) {
    for (i = 0; i < rate / 8; i++) {
      uint64_t lane = 0;
      memcpy(&lane, in + i * 8, 8);
      st[i] ^= lane;
    }
    keccak_f(st);
    in += rate;
    inlen -= rate;
  }
  {
    uint8_t blk[200];
    memset(blk, 0, sizeof blk);
    if (inlen && in) memcpy(blk, in, inlen);
    blk[inlen] ^= ds;
    blk[rate - 1] ^= 0x80;
    for (i = 0; i < rate / 8; i++) {
      uint64_t lane = 0;
      memcpy(&lane, blk + i * 8, 8);
      st[i] ^= lane;
    }
  }
  keccak_f(st);
  while (outlen > 0) {
    n = outlen < rate ? outlen : rate;
    memcpy(out, st, n);
    out += n;
    outlen -= n;
    if (outlen > 0) keccak_f(st);
  }
}

void oo_sha3_256_bytes(const uint8_t *in, size_t n, uint8_t out[32]) {
  keccak_absorb_squeeze(in, n, out, 32, 136, 0x06);
}
void oo_sha3_512_bytes(const uint8_t *in, size_t n, uint8_t out[64]) {
  keccak_absorb_squeeze(in, n, out, 64, 72, 0x06);
}
void oo_shake128(const uint8_t *in, size_t n, uint8_t *out, size_t outn) {
  keccak_absorb_squeeze(in, n, out, outn, 168, 0x1f);
}
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn) {
  keccak_absorb_squeeze(in, n, out, outn, 136, 0x1f);
}

static OoStr oo_crypto_hex(const uint8_t *d, size_t n) {
  static const char *hx = "0123456789abcdef";
  char *buf = oo_str_alloc_payload(n * 2);
  size_t i;
  for (i = 0; i < n; i++) {
    buf[i * 2] = hx[(d[i] >> 4) & 0xf];
    buf[i * 2 + 1] = hx[d[i] & 0xf];
  }
  { OoStr r; r.data = buf; r.len = (long long)(n * 2); return r; }
}

OoStr crypto_sha3_256_internal(OoStr data) {
  uint8_t dgst[32];
  oo_sha3_256_bytes((const uint8_t *)(data.data ? data.data : ""),
                    data.data && data.len > 0 ? (size_t)data.len : 0, dgst);
  return oo_crypto_hex(dgst, 32);
}
