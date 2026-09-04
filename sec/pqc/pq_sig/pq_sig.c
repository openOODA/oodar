/* Post-Quantum Cap Seal — shared utilities. This TU has no public API;
 * it owns the size constants and the OoStr hex I/O glue shared by
 * pq_hmac.c and pq_aead.c.
 *
 * The actual HMAC and AEAD seal/orchestration live in the sibling
 * TUs (pq_hmac.c, pq_aead.c). pq_hmac.c exposes the
 * crypto_pq_hmac_sha256_*_internal family; pq_aead.c exposes the
 * crypto_pq_aead_seal/open family. Both depend on the constants
 * and hex helpers defined here.
 */
#include "../../../oodar.h"
#include <stdint.h>

/* ML-DSA-65 sizes — FIPS 204 §5 (ML-DSA-65 parameter set). */
#define PQ_SEED_LEN 32
#define PQ_PK_LEN 1952
#define PQ_SK_LEN 4032
#define PQ_SIG_LEN 3309
#define PQ_SEAL_HEX_LEN ((PQ_PK_LEN + PQ_SIG_LEN) * 2) /* 10522 */

/* AES-128-GCM parameters (NIST SP 800-38D). */
#define AEAD_KEY_LEN 16
#define AEAD_NONCE_LEN 12
#define AEAD_TAG_LEN 16
#define CONF_SEAL_OVERHEAD (PQ_PK_LEN + AEAD_NONCE_LEN + AEAD_TAG_LEN + PQ_SIG_LEN) /* 5289 */

/* Hex digit helper (one nibble of ASCII hex). */
int hex_digit(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Decode a `want`-byte binary from a 2*want-character hex string.
 * Returns 1 on success, 0 on bad length or non-hex character. */
int hex_load_n(const char *s, size_t slen, uint8_t *out, size_t want) {
  if (!s || slen != want * 2) return 0;
  for (size_t i = 0; i < want; i++) {
    int hi = hex_digit((unsigned char)s[2 * i]);
    int lo = hex_digit((unsigned char)s[2 * i + 1]);
    if (hi < 0 || lo < 0) return 0;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 1;
}

/* Encode n binary bytes as 2n hex chars. Allocates an oo_str payload. */
OoStr hex_out_n(const uint8_t *p, size_t n) {
  static const char *hx = "0123456789abcdef";
  char *buf = oo_str_alloc_payload(n * 2);
  for (size_t i = 0; i < n; i++) {
    buf[i * 2] = hx[(p[i] >> 4) & 0xf];
    buf[i * 2 + 1] = hx[p[i] & 0xf];
  }
  OoStr r; r.data = buf; r.len = (long long)(n * 2); return r;
}
