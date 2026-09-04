/* M17: process-local AllocCap — explicit alloc helpers only.
 * Not OS rlimit / heap isolation / ASAN.
 * Ambient List growth is quota-bounded (list); alloc_bytes raises ceiling.
 *
 * v3.4.0 round-6: the AllocCap subsystem (oo_cap_grant_alloc /
 * oo_cap_require_alloc / oo_cap_is_alloc + the g_tok_alloc state +
 * the OO_CLASSIC_ALLOC magic) moved to sec/cap/cap_alloc.c per the
 * misplaced-files audit. The allocator just calls oo_cap_require_alloc()
 * and stays out of the cap store. */
#include "../../oodar.h"
#include <unistd.h>
#include <pthread.h>
#include <limits.h>

/* CHANGE B: quota counter is shared process state. Wrap the read-modify-
 * write of oo_list_ambient_quota in a mutex so concurrent alloc_bytes /
 * free_bytes callers cannot lose updates. The mutex lives in list/list.c
 * (where the ambient-quota state is owned); declared extern here. */
extern pthread_mutex_t g_quota_mu;
extern long long oo_list_ambient_quota;
extern long long oo_list_ambient_bytes;
extern void oo_list_quota_init_public(void);

/* Per-raise ceiling for oo_alloc_bytes (bytes). Related to ambient List quota
 * (default 64MiB in list; raised process-locally via this helper).
 * Residual: not OS rlimit / setrlimit / cgroup heap isolation — process-local
 * ambient counter only. Full OS heap policy remains DESIGN. */
#define OO_ALLOC_BYTES_MAX (1LL << 30) /* 1 GiB per raise */

/* Smoke-friendly: re-check cap then return n as opaque size token (not real mmap).
 * Raises ambient List ceiling after env init (so OO_LIST_AMBIENT_QUOTA is base).
 * n < 0 or n > OO_ALLOC_BYTES_MAX → clamp to 0 (no-op raise).
 * Quota add saturates at LLONG_MAX (no signed overflow wrap). */
long long oo_alloc_bytes(long long cap, long long n) {
  oo_cap_require_alloc(cap, "alloc_bytes");
  if (n < 0) n = 0;
  if (n > OO_ALLOC_BYTES_MAX) n = 0; /* oversize: no-op raise (not OS rlimit) */
  oo_list_quota_init_public();
  pthread_mutex_lock(&g_quota_mu);
  /* Sprint 1.7: check before add; saturate at LLONG_MAX on overflow. */
  if (n > LLONG_MAX - oo_list_ambient_quota)
    oo_list_ambient_quota = LLONG_MAX;
  else
    oo_list_ambient_quota += n;
  pthread_mutex_unlock(&g_quota_mu);
  return n;
}

/* Smoke-friendly: re-check cap; free is a no-op by handle.
 * Negative p must not inflate ambient quota (Seventh queue CRIT).
 * Sprint 1.6: oversize free (p > quota) is a no-op reclaim — leave quota
 * unchanged. Only subtract when p <= quota (exact free-to-zero is allowed). */
void oo_free_bytes(long long cap, long long p) {
  oo_cap_require_alloc(cap, "free_bytes");
  if (p < 0) p = 0;
  pthread_mutex_lock(&g_quota_mu);
  if (p <= oo_list_ambient_quota) {
    oo_list_ambient_quota -= p;
  }
  /* else: p > quota → reject oversize free as no-op reclaim */
  pthread_mutex_unlock(&g_quota_mu);
}

/* ========================================================================= */
/* Milestone 2: Direct Heap Allocation Primitives with Quota & Bounds Safety */
/* ========================================================================= */

typedef struct OoRawAllocHeader {
  size_t total_size;
  size_t capacity;
  uint64_t magic;
  uintptr_t user_ptr;
  struct OoRawAllocHeader *next;
  uint64_t pad;
} OoRawAllocHeader;

#define OO_RAW_ALLOC_MAGIC 0x4F4F414C4C4F4331ULL /* "OOALLOC1" */
#define OO_ALLOC_BUCKETS 1024
static OoRawAllocHeader *g_alloc_table[OO_ALLOC_BUCKETS];

long long oo_alloc(long long cap, long long size) {
  oo_cap_require_alloc(cap, "alloc");
  if (size <= 0 || size > OO_ALLOC_BYTES_MAX) return 0;
  oo_list_quota_init_public();
  size_t total_sz = sizeof(OoRawAllocHeader) + (size_t)size;
  if (total_sz % 16 != 0) total_sz += 16 - (total_sz % 16);

  pthread_mutex_lock(&g_quota_mu);
  /* v3.1.0 audit fix: guard the signed long long addition against
   * wrap. If oo_list_ambient_bytes + total_sz overflows LLONG_MAX,
   * the comparison flips to a small negative and the quota check
   * is bypassed. Bounded by the prior `size > OO_ALLOC_BYTES_MAX`
   * check (1 GiB), so the wrap can only happen if the ambient
   * counter is set near LLONG_MAX via OO_LIST_AMBIENT_QUOTA env. */
  if (oo_list_ambient_bytes > oo_list_ambient_quota - (long long)total_sz) {
    pthread_mutex_unlock(&g_quota_mu);
    fprintf(stderr, "ERR\tcap\tambient memory quota exceeded (AllocCap required)\n");
    exit(1);
  }
  oo_list_ambient_bytes += (long long)total_sz;

  void *raw = NULL;
  if (posix_memalign(&raw, 16, total_sz) != 0 || !raw) {
    oo_list_ambient_bytes -= (long long)total_sz;
    pthread_mutex_unlock(&g_quota_mu);
    return 0;
  }

  memset(raw, 0, total_sz);
  OoRawAllocHeader *hdr = (OoRawAllocHeader *)raw;
  hdr->total_size = total_sz;
  hdr->capacity = (size_t)size;
  hdr->magic = OO_RAW_ALLOC_MAGIC;
  void *user_ptr = (char *)raw + sizeof(OoRawAllocHeader);
  hdr->user_ptr = (uintptr_t)user_ptr;

  size_t b = (((uintptr_t)user_ptr) >> 4) % OO_ALLOC_BUCKETS;
  hdr->next = g_alloc_table[b];
  g_alloc_table[b] = hdr;
  pthread_mutex_unlock(&g_quota_mu);

  return (long long)(uintptr_t)user_ptr;
}

void oo_free(long long cap, long long ptr) {
  oo_cap_require_alloc(cap, "free");
  if (!ptr) return;
  uintptr_t target = (uintptr_t)ptr;
  size_t b = (target >> 4) % OO_ALLOC_BUCKETS;

  pthread_mutex_lock(&g_quota_mu);
  OoRawAllocHeader **curr = &g_alloc_table[b];
  while (*curr) {
    if ((*curr)->user_ptr == target) {
      OoRawAllocHeader *hdr = *curr;
      *curr = hdr->next;
      size_t total_sz = hdr->total_size;
      oo_list_ambient_bytes -= (long long)total_sz;
      if (oo_list_ambient_bytes < 0) oo_list_ambient_bytes = 0;
      pthread_mutex_unlock(&g_quota_mu);
      free(hdr);
      return;
    }
    curr = &(*curr)->next;
  }
  pthread_mutex_unlock(&g_quota_mu);
}

void (oo_write_int)(long long cap, long long ptr, long long offset, long long val) {
  oo_cap_require_alloc(cap, "write_int");
  if (!ptr) { fprintf(stderr, "ERR\tmem\tnull pointer dereference in oo_write_int\n"); exit(1); }
  if (offset < 0) { fprintf(stderr, "ERR\tmem\tnegative offset in oo_write_int\n"); exit(1); }
  OoRawAllocHeader *hdr = (OoRawAllocHeader *)((char *)(uintptr_t)ptr - sizeof(OoRawAllocHeader));
  /* v2.1.0: the bounds check is now mandatory regardless of magic. Previously
   * (&&) meant a foreign pointer (magic mismatch) silently bypassed the
   * bounds check, giving any AllocCap holder arbitrary R/W into the
   * process. Now: magic MUST match AND offset+sizeof must fit, both
   * independently. */
  if (hdr->magic != OO_RAW_ALLOC_MAGIC) {
    fprintf(stderr, "ERR\tmem\tforeign pointer (bad magic) in oo_write_int — refused\n");
    exit(1);
  }
  if ((size_t)offset + sizeof(long long) > hdr->capacity) {
    fprintf(stderr, "ERR\tmem\tout of bounds write in oo_write_int\n");
    exit(1);
  }
  long long *dest = (long long *)((char *)(uintptr_t)ptr + offset);
  *dest = val;
}

long long (oo_read_int)(long long cap, long long ptr, long long offset) {
  oo_cap_require_alloc(cap, "read_int");
  if (!ptr) { fprintf(stderr, "ERR\tmem\tnull pointer dereference in oo_read_int\n"); exit(1); }
  if (offset < 0) { fprintf(stderr, "ERR\tmem\tnegative offset in oo_read_int\n"); exit(1); }
  OoRawAllocHeader *hdr = (OoRawAllocHeader *)((char *)(uintptr_t)ptr - sizeof(OoRawAllocHeader));
  if (hdr->magic != OO_RAW_ALLOC_MAGIC) {
    fprintf(stderr, "ERR\tmem\tforeign pointer (bad magic) in oo_read_int — refused\n");
    exit(1);
  }
  if ((size_t)offset + sizeof(long long) > hdr->capacity) {
    fprintf(stderr, "ERR\tmem\tout of bounds read in oo_read_int\n");
    exit(1);
  }
  long long *src = (long long *)((char *)(uintptr_t)ptr + offset);
  return *src;
}

