#ifndef MLKEM_INTERNAL_H
#define MLKEM_INTERNAL_H
#include "../../../oodar.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define KQ 3329
#define KN 256
#define KK 3
#define KETA1 2
#define KETA2 2
#define KDU 10
#define KDV 4
#define KSS 32
#define KPK 1184
#define KSK 2400
#define KCIPHERTEXT 1088
#define KPOLYBYTES 384
#define KPOLYVECBYTES 1152
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void oo_shake128(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
#endif
