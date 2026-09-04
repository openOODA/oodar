/* HMAC-SHA256 (RFC 2104) construction.
 *
 * v2.3.0 file split: extracted from the monolithic sec/crypto/crypto.c.
 * Depends on sha256_bytes defined in symmetric/hash.c and on
 * crypto_secure_wipe from symmetric/secure.c; the umbrella must
 * include secure.c and hash.c before this file. */
#include "../../../oodar.h"
#include "../crypto_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

OoStr crypto_hmac_sha256_internal(OoStr key, OoStr msg) {
  unsigned char k[64];
  OoStr empty;
  empty.data = NULL;
  empty.len = 0;
  if (key.len < 0 || msg.len < 0) return empty;
  memset(k, 0, 64);
  if ((size_t)key.len > 64) sha256_bytes((const unsigned char *)key.data, (size_t)key.len, k);
  else if (key.len > 0 && key.data) memcpy(k, key.data, (size_t)key.len);

  unsigned char ipad[64], opad[64];
  for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

  size_t inner_len = 64 + (size_t)msg.len;
  unsigned char *inner_buf = (unsigned char *)malloc(inner_len);
  if (!inner_buf) abort();
  memcpy(inner_buf, ipad, 64);
  if (msg.len > 0 && msg.data) memcpy(inner_buf + 64, msg.data, (size_t)msg.len);

  unsigned char inner_digest[32];
  sha256_bytes(inner_buf, inner_len, inner_digest);
  crypto_secure_wipe(inner_buf, inner_len);
  free(inner_buf);

  unsigned char outer_buf[64 + 32];
  memcpy(outer_buf, opad, 64);
  memcpy(outer_buf + 64, inner_digest, 32);

  unsigned char outer_digest[32];
  sha256_bytes(outer_buf, 64 + 32, outer_digest);

  /* Wipe key material and intermediate HMAC state before return. */
  crypto_secure_wipe(k, sizeof(k));
  crypto_secure_wipe(ipad, sizeof(ipad));
  crypto_secure_wipe(opad, sizeof(opad));
  crypto_secure_wipe(outer_buf, sizeof(outer_buf));
  crypto_secure_wipe(inner_digest, sizeof(inner_digest));

  char *hex = oo_str_alloc_payload(64);
  for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", outer_digest[i]);
  hex[64] = '\0';
  crypto_secure_wipe(outer_digest, sizeof(outer_digest));
  OoStr r; r.data = hex; r.len = 64; return r;
}
