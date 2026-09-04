/* AEAD orchestrator — shared input parsing / output formatting for the
 * AES-GCM and ChaCha20-Poly1305 implementations below.
 *
 * v2.3.0 file split: the AES-GCM seal/open (NIST SP 800-38D) live in
 * aes_gcm.c; the ChaCha20-Poly1305 seal/open (RFC 8439) live in
 * chacha20_poly1305.c. Both consume the hex/binary load and cat helpers
 * defined here, so this file must be included before the implementation
 * files in the umbrella (see oodar.c). */
#include "../../../oodar.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
