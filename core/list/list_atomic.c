/* v2.3.0 split: atomic refcount protocol for OoIList / OoSList. Owns the
 * retain / release / free family; the CAS loop guards against a concurrent
 * release-to-zero racing with a retain. On release-to-zero the slot is
 * tombstoned (flags=UINT32_MAX) and a release fence ensures the tombstone
 * is globally visible before free() — CRIT-1 in core/list history. */
#include "../../oodar.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

extern pthread_mutex_t g_quota_mu;
extern long long oo_list_ambient_bytes;
extern long long oo_list_block_bytes(long long cap, size_t elem);

/* Forward decls of the refcount-state helpers in list.c (orchestrator). */
static int oo_list_hdr_ok(void *data, long long len, long long cap);
static int oo_list_owned(void *data);

void oo_ilist_retain(OoIList l) {
  if (!l.data) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);
  uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);
  if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  /* CAS loop so a concurrent release-to-zero cannot be lost. */
  while (rc > 0 && rc < UINT32_MAX) {
    if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1,
                                    __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
      return;
    }
    rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);
    fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);
    if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  }
}

void oo_ilist_release(OoIList l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    /* CRIT-1: ARM/POWER can reorder free() before the flags store above.
     * An explicit release fence guarantees the tombstone is globally
     * visible before the slot is reclaimed, without paying for SEQ_CST. */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(long long));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

void oo_ilist_free(OoIList l) {
  oo_ilist_release(l);
}

void oo_slist_retain(OoSList l) {
  if (!l.data) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);
  uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);
  if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  while (rc > 0 && rc < UINT32_MAX) {
    if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1,
                                    __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
      return;
    }
    rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);
    fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);
    if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  }
}

void oo_slist_release(OoSList l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) {
      oo_str_release(l.data[i]);
    }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    /* CRIT-1: see oo_ilist_release; same fence rationale. */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoStr));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

void oo_slist_free(OoSList l) {
  oo_slist_release(l);
}
