/* M161: MD5 + SHA-1 pure digests (hex). AES residual stays fail-closed string elsewhere. */
#include "../../oodar.h"

#define LR(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

static OoStr hex_encode_n(const unsigned char *d, size_t n) {
  static const char *hx = "0123456789abcdef";
  char *buf = oo_str_alloc_payload(n * 2);
  size_t i;
  for (i = 0; i < n; i++) {
    buf[i * 2] = hx[(d[i] >> 4) & 0xf];
    buf[i * 2 + 1] = hx[d[i] & 0xf];
  }
  OoStr r;
  r.data = buf;
  r.len = (long long)(n * 2);
  return r;
}

static void md5_bytes(const unsigned char *initial_msg, size_t initial_len, unsigned char *digest) {
  uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;
  size_t new_len, offset;
  uint64_t bits_len;
  unsigned char *msg = NULL;
  static const uint32_t r[] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
  static const uint32_t k[] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
  new_len = ((((initial_len + 8) / 64) + 1) * 64) - 8;
  msg = (unsigned char *)calloc(new_len + 64, 1);
  if (!msg) abort();
  if (initial_len && initial_msg) memcpy(msg, initial_msg, initial_len);
  msg[initial_len] = 128;
  bits_len = (uint64_t)initial_len * 8;
  memcpy(msg + new_len, &bits_len, 8);
  for (offset = 0; offset < new_len; offset += 64) {
    uint32_t *w = (uint32_t *)(msg + offset);
    uint32_t a = h0, b = h1, c = h2, d = h3, i, f, g, temp;
    for (i = 0; i < 64; i++) {
      if (i < 16) { f = (b & c) | ((~b) & d); g = i; }
      else if (i < 32) { f = (d & b) | ((~d) & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | (~d)); g = (7 * i) % 16; }
      temp = d; d = c; c = b;
      b = b + LR((a + f + k[i] + w[g]), r[i]);
      a = temp;
    }
    h0 += a; h1 += b; h2 += c; h3 += d;
  }
  free(msg);
  memcpy(digest, &h0, 4); memcpy(digest + 4, &h1, 4);
  memcpy(digest + 8, &h2, 4); memcpy(digest + 12, &h3, 4);
}

OoStr crypto_md5_internal(OoStr data) {
  unsigned char dig[16];
  const unsigned char *p = (const unsigned char *)(data.data ? data.data : "");
  size_t n;
  if (data.len < 0) {
    OoStr empty;
    empty.data = NULL;
    empty.len = 0;
    return empty;
  }
  n = data.data ? (size_t)data.len : 0;
  md5_bytes(p, n, dig);
  return hex_encode_n(dig, 16);
}

static void sha1_bytes(const unsigned char *str, size_t len, unsigned char *hash) {
  uint32_t h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0;
  uint64_t ml = (uint64_t)len * 8;
  size_t pad = (len % 64 < 56) ? (56 - len % 64) : (120 - len % 64);
  size_t total = len + pad + 8;
  unsigned char *msg = (unsigned char *)calloc(total, 1);
  size_t i, chunk;
  if (!msg) abort();
  if (len && str) memcpy(msg, str, len);
  msg[len] = 0x80;
  /* G7 fix: SHA-1 length field is big-endian (per FIPS 180-4 §5.1.1).
   * The old code wrote it little-endian, which only matched known
   * vectors for inputs under 32 bytes (where the length fits in 1 byte). */
  for (i = 0; i < 8; i++) msg[total - 8 + i] = (unsigned char)((ml >> (8 * (7 - i))) & 0xff);
  for (chunk = 0; chunk < total; chunk += 64) {
    uint32_t w[80], a,b,c,d,e,f,k,temp;
    for (i = 0; i < 16; i++) {
      w[i] = ((uint32_t)msg[chunk+i*4]<<24)|((uint32_t)msg[chunk+i*4+1]<<16)|
             ((uint32_t)msg[chunk+i*4+2]<<8)|(uint32_t)msg[chunk+i*4+3];
    }
    for (i = 16; i < 80; i++) {
      temp = w[i-3]^w[i-8]^w[i-14]^w[i-16];
      w[i] = LR(temp, 1);
    }
    a=h0;b=h1;c=h2;d=h3;e=h4;
    for (i = 0; i < 80; i++) {
      if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6; }
      temp = LR(a, 5) + f + e + k + w[i];
      e = d; d = c; c = LR(b, 30); b = a; a = temp;
    }
    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
  }
  free(msg);
  for (i = 0; i < 4; i++) {
    hash[i] = (h0 >> (24 - i * 8)) & 0xFF;
    hash[4 + i] = (h1 >> (24 - i * 8)) & 0xFF;
    hash[8 + i] = (h2 >> (24 - i * 8)) & 0xFF;
    hash[12 + i] = (h3 >> (24 - i * 8)) & 0xFF;
    hash[16 + i] = (h4 >> (24 - i * 8)) & 0xFF;
  }
}

OoStr crypto_sha1_internal(OoStr data) {
  unsigned char dig[20];
  const unsigned char *p = (const unsigned char *)(data.data ? data.data : "");
  size_t n;
  if (data.len < 0) {
    OoStr empty;
    empty.data = NULL;
    empty.len = 0;
    return empty;
  }
  n = data.data ? (size_t)data.len : 0;
  sha1_bytes(p, n, dig);
  return hex_encode_n(dig, 20);
}

/* Path A AES-128-ECB (M162): key len==16, plain len multiple of 16 and >0.
 * Residual: other modes/padding/IV — return STUB_FAIL_CLOSED. */
static const uint8_t aes_sbox[256] = {
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
static const uint8_t aes_rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t aes_xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ (((uint8_t)(0u - (unsigned)(x >> 7))) & 0x1b));
}

static void aes_key_expand(const uint8_t *key, uint8_t rk[176]) {
  int i;
  uint8_t t[4];
  memcpy(rk, key, 16);
  for (i = 4; i < 44; i++) {
    t[0]=rk[4*(i-1)]; t[1]=rk[4*(i-1)+1]; t[2]=rk[4*(i-1)+2]; t[3]=rk[4*(i-1)+3];
    if (i % 4 == 0) {
      uint8_t u = t[0];
      t[0] = aes_sbox[t[1]] ^ aes_rcon[i/4];
      t[1] = aes_sbox[t[2]];
      t[2] = aes_sbox[t[3]];
      t[3] = aes_sbox[u];
    }
    rk[4*i]   = rk[4*(i-4)]   ^ t[0];
    rk[4*i+1] = rk[4*(i-4)+1] ^ t[1];
    rk[4*i+2] = rk[4*(i-4)+2] ^ t[2];
    rk[4*i+3] = rk[4*(i-4)+3] ^ t[3];
  }
}

static void aes_block_encrypt(const uint8_t *in, const uint8_t rk[176], uint8_t *out) {
  uint8_t s[16];
  int round, i;
  memcpy(s, in, 16);
  for (i = 0; i < 16; i++) s[i] ^= rk[i];
  for (round = 1; round <= 10; round++) {
    for (i = 0; i < 16; i++) s[i] = aes_sbox[s[i]];
    { uint8_t t;
      t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
      t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
      t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t; }
    if (round < 10) {
      for (i = 0; i < 16; i += 4) {
        uint8_t a=s[i], b=s[i+1], c=s[i+2], d=s[i+3];
        s[i]   = (uint8_t)(aes_xtime(a) ^ aes_xtime(b) ^ b ^ c ^ d);
        s[i+1] = (uint8_t)(a ^ aes_xtime(b) ^ aes_xtime(c) ^ c ^ d);
        s[i+2] = (uint8_t)(a ^ b ^ aes_xtime(c) ^ aes_xtime(d) ^ d);
        s[i+3] = (uint8_t)(aes_xtime(a) ^ a ^ b ^ c ^ aes_xtime(d));
      }
    }
    for (i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
  }
  memcpy(out, s, 16);
}

OoStr crypto_aes_encrypt_internal(OoStr key, OoStr plain) {
  uint8_t rk[176];
  size_t kn, pn, off;
  if (key.len < 0 || plain.len < 0) {
    return oo_str_lit("STUB_FAIL_CLOSED");
  }
  unsigned char *out;
  const unsigned char *k, *p;
  kn = key.data ? (size_t)key.len : 0;
  pn = plain.data ? (size_t)plain.len : 0;
  k = (const unsigned char *)(key.data ? key.data : "");
  p = (const unsigned char *)(plain.data ? plain.data : "");
  if (kn != 16 || pn == 0 || (pn % 16) != 0) {
    return oo_str_lit("STUB_FAIL_CLOSED");
  }
  aes_key_expand(k, rk);
  out = (unsigned char *)malloc(pn);
  if (!out) abort();
  for (off = 0; off < pn; off += 16) {
    aes_block_encrypt(p + off, rk, out + off);
  }
  {
    OoStr hex = hex_encode_n(out, pn);
    free(out);
    return hex;
  }
}
