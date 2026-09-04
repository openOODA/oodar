#ifndef OODAR_CRYPTO_INTERNAL_H
#define OODAR_CRYPTO_INTERNAL_H
/* Private header for crypto_*_internal primitives.
 *
 * v2.0.0 Floor break: these symbols are no longer in oodar.h.
 * They are visible to .c files in the umbrella (which include this
 * header) but NOT to external consumers. Use the public
 * cap-gated wrappers (e.g., oo_seal, oo_open) instead. */
#include "../../types.h"

OoStr crypto_md5_internal(OoStr data);
OoStr crypto_sha1_internal(OoStr data);
OoStr crypto_aes_encrypt_internal(OoStr key, OoStr plain);
OoStr crypto_sha256_internal(OoStr data);
OoStr crypto_sha512_internal(OoStr data);
OoStr crypto_hmac_sha256_internal(OoStr key, OoStr msg);
void crypto_secure_wipe(void *p, size_t n);
int crypto_ct_cmp(const void *a, const void *b, size_t n);
OoStr crypto_sha3_256_internal(OoStr data);
OoStr crypto_aes_gcm_seal_internal(OoStr key, OoStr nonce, OoStr pt, OoStr aad);
OoStr crypto_aes_gcm_open_internal(OoStr key, OoStr nonce, OoStr ct, OoStr tag, OoStr aad);
OoStr crypto_chacha20poly1305_seal_internal(OoStr key, OoStr nonce, OoStr pt, OoStr aad);
OoStr crypto_chacha20poly1305_open_internal(OoStr key, OoStr nonce, OoStr ct, OoStr tag, OoStr aad);
OoStr crypto_mlkem768_keygen_internal(OoStr dz);
OoStr crypto_mlkem768_encaps_internal(OoStr ek, OoStr m);
OoStr crypto_mlkem768_decaps_internal(OoStr dk, OoStr ct);
OoStr crypto_mldsa65_keygen_internal(OoStr seed);
OoStr crypto_mldsa65_sign_internal(OoStr sk, OoStr msg, OoStr rnd);
OoStr crypto_mldsa65_verify_internal(OoStr pk, OoStr msg, OoStr sig);
OoStr crypto_pq_hmac_sha256_internal(OoStr key, OoStr msg);
int crypto_pq_hmac_sha256_verify_internal(OoStr seal, OoStr msg);
int crypto_pq_hmac_self_test(void);
OoStr crypto_pq_aead_seal_internal(OoStr cap_key32, OoStr aead_key16, OoStr plaintext);
OoStr crypto_pq_aead_open_internal(OoStr cap_key32, OoStr aead_key16, OoStr seal);

#endif
