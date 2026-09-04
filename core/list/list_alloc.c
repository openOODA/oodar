/* v2.3.0 split: ambient-quota-aware list payload allocator and the matching
 * quota-byte release. Sits between the align.c raw posix_memalign allocator
 * and the list_atomic.c refcount protocol. Owns no static state; reads /
 * writes the g_quota_mu / oo_list_ambient_bytes state in list.c via extern.
 * Fail-closed: on quota overflow, prints to stderr and exits (1). */
#include "../../oodar.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

extern pthread_mutex_t g_quota_mu;
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
  pthread_mutex_lock(&g_quota_mu);
  if (oo_list_ambient_bytes + charge > oo_list_ambient_quota) {
    pthread_mutex_unlock(&g_quota_mu);
    fprintf(stderr, "ERR\tcap\tambient List memory quota exceeded (AllocCap required)\n");
    exit(1);
  }
  oo_list_ambient_bytes += charge;
  pthread_mutex_unlock(&g_quota_mu);
  pay = oo_payload_alloc(sizeof(OoListHeader), cap * elem_size);
  hdr = ((OoListHeader *)pay) - 1;
  __atomic_store_n(&hdr->ref_count, 0, __ATOMIC_RELEASE);
  __atomic_store_n(&hdr->flags, 0, __ATOMIC_RELEASE);
  return pay;
}

void oo_list_quota_release_bytes(long long cap, size_t elem_size) {
  if (cap <= 0) return;
  pthread_mutex_lock(&g_quota_mu);
  oo_list_ambient_bytes -= oo_list_block_bytes(cap, elem_size);
  if (oo_list_ambient_bytes < 0) oo_list_ambient_bytes = 0;
  pthread_mutex_unlock(&g_quota_mu);
}
