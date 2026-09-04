/* 64-byte aligned string/list payloads. Header layout is unchanged:
 * payload sits 64 bytes into the block; OoStrHeader/OoListHeader is
 * immediately before the payload (8-16 bytes). free() the 64-aligned block. */
#include "chs_rt.h"
#include <stdint.h>
#include <errno.h>

#ifndef OO_PAYLOAD_ALIGN
#define OO_PAYLOAD_ALIGN 64
#endif

void *oo_payload_alloc(size_t hdr_sz, size_t payload_sz) {
  size_t n;
  void *blk = NULL;
  char *pay;
  (void)hdr_sz;
  if (payload_sz > (SIZE_MAX - OO_PAYLOAD_ALIGN - 1)) abort();
  n = OO_PAYLOAD_ALIGN + payload_sz;
  if (n % OO_PAYLOAD_ALIGN) n += OO_PAYLOAD_ALIGN - (n % OO_PAYLOAD_ALIGN);
  if (posix_memalign(&blk, OO_PAYLOAD_ALIGN, n) != 0) abort();
  memset(blk, 0, n);
  pay = (char *)blk + OO_PAYLOAD_ALIGN;
  return pay;
}

void oo_payload_free(void *payload) {
  if (!payload) return;
  free((char *)payload - OO_PAYLOAD_ALIGN);
}

int oo_payload_aligned(const void *p) {
  if (!p) return 0;
  return (((uintptr_t)p) & (OO_PAYLOAD_ALIGN - 1)) == 0;
}

long long oo_list_block_bytes(long long cap, size_t elem) {
  if (cap <= 0) return 0;
  return (long long)OO_PAYLOAD_ALIGN + cap * (long long)elem;
}
