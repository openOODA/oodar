/* SHA-256 and SHA-512 hash primitives (NIST FIPS 180-4).
 *
 * v2.3.0 file split: extracted from the monolithic sec/crypto/crypto.c.
 * The legacy MD5 and SHA-1 implementations remain in sec/crypto/hash.c
 * (they were not in crypto.c — kept untouched per the v2.3.0 spec).
 * crypto_secure_wipe / crypto_ct_cmp live in symmetric/secure.c
 * (must be #included first in the umbrella). */
#include "../../../oodar.h"
#include "../crypto_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Genuine NIST FIPS 180-4 SHA-256 Implementation */

static const uint32_t K256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void sha256_bytes(const unsigned char *data, size_t len, unsigned char out[32]) {
  uint32_t s[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  uint64_t bitlen = (uint64_t)len * 8;
  size_t pad_len = len + 1;
  while ((pad_len % 64) != 56) pad_len++;
  size_t total_len = pad_len + 8;

  unsigned char *buf = (unsigned char *)calloc(total_len, 1);
  if (!buf) abort();
  if (len > 0 && data) memcpy(buf, data, len);
  buf[len] = 0x80;

  for (int i = 0; i < 8; i++) buf[total_len - 1 - i] = (unsigned char)(bitlen >> (i * 8));

  for (size_t offset = 0; offset < total_len; offset += 64) {
    uint32_t W[64];
    const unsigned char *p = buf + offset;
    for (int i = 0; i < 16; i++)
      W[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | ((uint32_t)p[i*4+3]);
    for (int i = 16; i < 64; i++)
      W[i] = W[i-16] + sigma0(W[i-15]) + W[i-7] + sigma1(W[i-2]);

    uint32_t a=s[0], b=s[1], c=s[2], d=s[3], e=s[4], f=s[5], g=s[6], h=s[7];
    for (int i = 0; i < 64; i++) {
      uint32_t T1 = h + SIGMA1(e) + CH(e, f, g) + K256[i] + W[i];
      uint32_t T2 = SIGMA0(a) + MAJ(a, b, c);
      h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
    crypto_secure_wipe(W, sizeof(W));
  }
  crypto_secure_wipe(buf, total_len);
  free(buf);
  for (int i = 0; i < 8; i++) {
    out[i*4] = (unsigned char)(s[i] >> 24); out[i*4+1] = (unsigned char)(s[i] >> 16);
    out[i*4+2] = (unsigned char)(s[i] >> 8); out[i*4+3] = (unsigned char)(s[i]);
  }
  crypto_secure_wipe(s, sizeof(s));
}

OoStr crypto_sha256_internal(OoStr data) {
  unsigned char digest[32];
  sha256_bytes((const unsigned char *)data.data, (size_t)data.len, digest);
  /* ARC: payload must be preceded by OoStrHeader (oo_str_alloc_payload). */
  char *hex = oo_str_alloc_payload(64);
  for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
  hex[64] = '\0';
  OoStr r; r.data = hex; r.len = 64; return r;
}

/* Genuine NIST FIPS 180-4 SHA-512 Implementation */

/* FIPS 180-4 §4.2.3: first 64 bits of the fractional parts of the cube roots
 * of the first 80 primes. K[21] low half is 6ea6e483, K[32] low half is 46d22ffc. */
static const uint64_t K512[80] = {
  0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
  0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
  0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
  0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0_64(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SIGMA1_64(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma0_64(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define sigma1_64(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

static void sha512_compress(uint64_t s[8], const unsigned char block[128]) {
  uint64_t W[80];
  int i;
  for (i = 0; i < 16; i++) {
    W[i] = ((uint64_t)block[i*8] << 56) | ((uint64_t)block[i*8+1] << 48) |
           ((uint64_t)block[i*8+2] << 40) | ((uint64_t)block[i*8+3] << 32) |
           ((uint64_t)block[i*8+4] << 24) | ((uint64_t)block[i*8+5] << 16) |
           ((uint64_t)block[i*8+6] << 8)  | ((uint64_t)block[i*8+7]);
  }
  for (i = 16; i < 80; i++) {
    W[i] = sigma1_64(W[i-2]) + W[i-7] + sigma0_64(W[i-15]) + W[i-16];
  }
  {
    uint64_t a=s[0], b=s[1], c=s[2], d=s[3], e=s[4], f=s[5], g=s[6], hh=s[7];
    for (i = 0; i < 80; i++) {
      uint64_t T1 = hh + SIGMA1_64(e) + CH64(e, f, g) + K512[i] + W[i];
      uint64_t T2 = SIGMA0_64(a) + MAJ64(a, b, c);
      hh = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=hh;
  }
  crypto_secure_wipe(W, sizeof(W));
}

static void sha512_bytes(const unsigned char *data, size_t len, unsigned char out[64]) {
  uint64_t s[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
  };
  uint64_t bitlen = (uint64_t)len * 8ULL;
  size_t pad_len = len + 1;
  size_t total_len;
  unsigned char *buf;
  size_t offset;
  int i;
  while ((pad_len % 128) != 112) pad_len++;
  total_len = pad_len + 16;
  buf = (unsigned char *)calloc(total_len, 1);
  if (!buf) abort();
  if (len > 0 && data) memcpy(buf, data, len);
  buf[len] = 0x80;
  for (i = 0; i < 8; i++) buf[total_len - 1 - i] = (unsigned char)(bitlen >> (i * 8));
  for (offset = 0; offset < total_len; offset += 128) sha512_compress(s, buf + offset);
  crypto_secure_wipe(buf, total_len);
  free(buf);
  for (i = 0; i < 8; i++) {
    out[i*8]   = (unsigned char)(s[i] >> 56); out[i*8+1] = (unsigned char)(s[i] >> 48);
    out[i*8+2] = (unsigned char)(s[i] >> 40); out[i*8+3] = (unsigned char)(s[i] >> 32);
    out[i*8+4] = (unsigned char)(s[i] >> 24); out[i*8+5] = (unsigned char)(s[i] >> 16);
    out[i*8+6] = (unsigned char)(s[i] >> 8);  out[i*8+7] = (unsigned char)(s[i]);
  }
  crypto_secure_wipe(s, sizeof(s));
}

OoStr crypto_sha512_internal(OoStr data) {
  unsigned char digest[64];
  sha512_bytes((const unsigned char *)data.data, (size_t)data.len, digest);
  char *hex = oo_str_alloc_payload(128);
  for (int i = 0; i < 64; i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
  hex[128] = '\0';
  OoStr r; r.data = hex; r.len = 128; return r;
}
