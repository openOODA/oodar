/* Secure memory primitives: zeroize and constant-time compare.
 *
 * v2.3.0 file split: extracted from the monolithic sec/crypto/crypto.c.
 * Used by all hash, HMAC, and AEAD implementations across sec/crypto/,
 * so this file must be #included first in the umbrella. */
#include "../../../oodar.h"
#include "../crypto_internal.h"
#include <stddef.h>
#if defined(__GLIBC__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <strings.h> /* explicit_bzero */
#endif

/* Wipe secrets: explicit_bzero when available, else volatile byte store (compiler-resistant). */
void crypto_secure_wipe(void *p, size_t n) {
  if (!p || n == 0) return;
#if defined(__GLIBC__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  explicit_bzero(p, n);
#else
  volatile unsigned char *v = (volatile unsigned char *)p;
  while (n--) *v++ = 0;
#endif
}

/* Data-independent compare: OR-of-XOR over all n bytes. Returns 0 iff equal. */
int crypto_ct_cmp(const void *a, const void *b, size_t n) {
  const volatile unsigned char *x = (const volatile unsigned char *)a;
  const volatile unsigned char *y = (const volatile unsigned char *)b;
  unsigned char d = 0;
  size_t i;
  if (!a || !b) return 1;
  for (i = 0; i < n; i++) d |= (unsigned char)(x[i] ^ y[i]);
  return (int)d;
}
