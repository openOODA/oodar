/* v2.3.0 split: orchestrator for OoIList / OoSList basic ops. Owns the
 * ambient-quota state and the static refcount-state helpers (oo_list_hdr_ok,
 * oo_list_owned). The atomic refcount primitives live in list_atomic.c,
 * the ambient-quota-aware allocator in list_alloc.c, and the COW set ops
 * in list_set.c. flist.c / llist.c are unchanged. */
#include "../../oodar.h"
#include <pthread.h>

/* Ambient-quota counter mutex across threads. */
pthread_mutex_t g_quota_mu = PTHREAD_MUTEX_INITIALIZER;
long long oo_list_ambient_quota = 64LL * 1024 * 1024;
long long oo_list_ambient_bytes = 0;

static pthread_once_t g_quota_once = PTHREAD_ONCE_INIT;

static void oo_list_quota_init_once(void) {
  const char *e = oo_process_policy_getenv("OO_LIST_AMBIENT_QUOTA");
  if (e && e[0]) {
    long long v = atoll(e);
    if (v > 0) oo_list_ambient_quota = v;
  }
}

void oo_list_quota_init_public(void) {
  pthread_once(&g_quota_once, oo_list_quota_init_once);
}

/* Refcount-state validation used by retain/release (list_atomic.c) and get
 * (here + llist.c / flist.c). Static so the symbol stays TU-local. */
static int oo_list_hdr_ok(void *data, long long len, long long cap) {
  if (!data) return 0;
  if (len < 0 || cap < 0 || len > (1LL << 28) || cap > (1LL << 28)) return 0;
  if (cap > 0 && len > cap) return 0;
  if (((uintptr_t)data) < sizeof(OoListHeader) + 8) return 0;
  OoListHeader *hdr = ((OoListHeader *)data) - 1;
  uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);
  if (rc == 0 || rc == UINT32_MAX) return 0;
  if (rc > 1000000u) return 0;
  if (__atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE) & 1) return 0;
  return 1;
}

/* "Is this payload exclusively owned (rc==1, no tombstone)?" — used by
 * mutating ops (push, set) to decide whether to write in place or COW. */
static int oo_list_owned(void *data) {
  OoListHeader *h = data ? ((OoListHeader *)data) - 1 : NULL;
  return h && __atomic_load_n(&h->ref_count, __ATOMIC_ACQUIRE) == 1
      && __atomic_load_n(&h->flags, __ATOMIC_ACQUIRE) == 0;
}

OoIList oo_ilist_new(void) {
  OoIList l = {NULL, 0, 0};
  return l;
}

OoIList oo_ilist_push(OoIList l, long long v) {
  OoIList n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v;
    l.len = l.len + 1;
    oo_ilist_retain(l);
    return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (long long *)oo_list_alloc_payload(sizeof(long long), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(long long));
  }
  n.data[l.len] = v;
  n.len = l.len + 1;
  n.cap = ncap;
  /* CRIT-2: publish payload then store rc=1 with release. */
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

long long oo_ilist_get(OoIList l, long long i) {
  /* CHANGE D: retain a reference across the read so a concurrent
   * release-to-zero from another thread cannot free the buffer while
   * we index into l.data. Release once read is complete. */
  oo_ilist_retain(l);
  long long v;
  if (i < 0 || i >= l.len) {
    oo_ilist_release(l);
    fprintf(stderr, "ERR\tilist_get OOB\n");
    exit(1);
  }
  v = l.data[i];
  oo_ilist_release(l);
  return v;
}

long long oo_ilist_len(OoIList l) { return l.len; }

OoSList oo_slist_new(void) {
  OoSList l = {NULL, 0, 0};
  (void)oo_sandbox_apply();
  return l;
}

OoSList oo_slist_push(OoSList l, OoStr v) {
  OoSList n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v;
    oo_str_retain(v);
    l.len = l.len + 1;
    oo_slist_retain(l);
    return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoStr *)oo_list_alloc_payload(sizeof(OoStr), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoStr));
    for (long long i = 0; i < l.len; i++) {
      oo_str_retain(n.data[i]);
    }
  }
  n.data[l.len] = v;
  oo_str_retain(v);
  n.len = l.len + 1;
  n.cap = ncap;
  /* CRIT-2: publish payload then store rc=1 with release. */
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

OoStr oo_slist_get(OoSList l, long long i) {
  /* CHANGE D: hold a list-level retain across the read so the underlying
   * payload cannot be freed mid-index by a concurrent release. */
  oo_slist_retain(l);
  OoStr r;
  if (i < 0 || i >= l.len) {
    oo_slist_release(l);
    fprintf(stderr, "ERR\tslist_get OOB: i=%lld, len=%lld\n", i, l.len);
    exit(1);
  }
  /* Return an owned ref so let s = list_get(...) is free-safe. */
  oo_str_retain(l.data[i]);
  r = l.data[i];
  oo_slist_release(l);
  return r;
}

long long oo_slist_len(OoSList l) { return l.len; }
