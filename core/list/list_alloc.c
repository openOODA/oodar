/* v2.3.0 split: ambient-quota-aware list payload allocator and the matching
 * quota-byte release. Sits between the align.c raw posix_memalign allocator
 * and the list_atomic.c refcount protocol. Owns no static state; reads /
 * writes the g_quota_mu / oo_list_ambient_bytes state in list.c via extern.
 * Fail-closed: on quota overflow, prints to stderr and exits (1). */
#include "../../oodar.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

extern long long oo_list_ambient_quota;
extern long long oo_list_ambient_bytes;
extern void oo_list_quota_init_public(void);

void *oo_list_alloc_payload(size_t elem_size, size_t cap) {
  void *pay;
  OoListHeader *hdr;
  long long charge;
  if (cap == 0) return NULL;
  charge = oo_list_block_bytes((long long)cap, elem_size);
  oo_list_quota_init_public();
  long long curr = __atomic_load_n(&oo_list_ambient_bytes, __ATOMIC_RELAXED);
  while (1) {
    if (curr + (long long)charge > oo_list_ambient_quota) {
      fprintf(stderr, "ERR\tcap\tambient List memory quota exceeded (AllocCap required)\n");
      exit(1);
    }
    if (__atomic_compare_exchange_n(&oo_list_ambient_bytes, &curr, curr + (long long)charge, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) break;
  }
  pay = oo_payload_alloc(sizeof(OoListHeader), cap * elem_size);
  hdr = ((OoListHeader *)pay) - 1;
  __atomic_store_n(&hdr->ref_count, 0, __ATOMIC_RELEASE);
  __atomic_store_n(&hdr->flags, 0, __ATOMIC_RELEASE);
  return pay;
}

void oo_list_quota_release_bytes(long long cap, size_t elem_size) {
  if (cap <= 0) return;
  long long bytes = oo_list_block_bytes(cap, elem_size);
  if (!bytes) return;
  __atomic_fetch_sub(&oo_list_ambient_bytes, (long long)bytes, __ATOMIC_RELEASE);
}
