#ifndef MLDSA_INTERNAL_H
#define MLDSA_INTERNAL_H
#include "../../../oodar.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define DQ 8380417
#define DN 256
#define DK 6
#define DL 5
#define DTAU 49
#define DETA 4
#define DBETA 196
#define DGAMMA1 (1 << 19)
#define DGAMMA2 261888
#define DOMEGA 55
#define DD 13
#define DCTILDE 48
#define DSEED 32
#define DTR 64
#define DRND 32
#define DPK 1952
#define DSK 4032
#define DSIG 3309
#define DPOLYT1 320
#define DPOLYT0 416
#define DPOLYETA 128
#define DPOLYZ 640
#define DPOLYW1 128
#define DQINV 58728449
void oo_shake256(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
void oo_shake128(const uint8_t *in, size_t n, uint8_t *out, size_t outn);
#endif
