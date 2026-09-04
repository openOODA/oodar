/* M17: process-local AllocCap — explicit alloc helpers only.
 * Not OS rlimit / heap isolation / ASAN.
 * Ambient List growth is quota-bounded (chs_rt_list); alloc_bytes raises ceiling. */
#include "chs_rt.h"
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

/* CHANGE A: pthread_once replaces ad-hoc g_alloc_ready guard. Eliminates
 * the init race between threads calling oo_cap_grant_alloc /
 * oo_cap_require_alloc concurrently. */
static pthread_once_t g_alloc_once = PTHREAD_ONCE_INIT;
static long long g_tok_alloc;

/* Classic forgeable magic OOAL — must never be the live token. */
#define OO_CLASSIC_ALLOC 0x4F4F414CLL

static void alloc_init_once(void) {
  unsigned char b[8];
  size_t i;
  unsigned long long acc;
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(b, sizeof b) != 0) {
    /* Fail-closed: no LCG fallback. getentropy() must succeed for unpredictable alloc token. */
    fprintf(stderr, "ERR\tcap\tgetentropy() failed; refusing to derive alloc capability token\n");
    abort();
  }
#else
  /* Fail-closed: no LCG fallback. getentropy() is required. */
  fprintf(stderr, "ERR\tcap\tgetentropy() not available; refusing to derive alloc capability token\n");
  abort();
#endif
  /* 0x7… band (fs=1 sys=2 env=3 net=4 time=5 rand=6 alloc=7) */
  {
    unsigned long long ent = ((((unsigned long long)b[0]) << 56) |
                              (((unsigned long long)b[1]) << 48) |
                              (((unsigned long long)b[2]) << 40) |
                              (((unsigned long long)b[3]) << 32) |
                              (((unsigned long long)b[4]) << 24) |
                              (((unsigned long long)b[5]) << 16) |
                              (((unsigned long long)b[6]) << 8)  |
                              ((unsigned long long)b[7])) & 0x00FFFFFFFFFFFFFFULL;
    g_tok_alloc = ((long long)(0x7 & 0x1F) << 56) | (long long)ent;
  }
  if (g_tok_alloc == OO_CLASSIC_ALLOC) g_tok_alloc ^= 0x11111111LL;
}

static void oo_alloc_init(void) {
  pthread_once(&g_alloc_once, alloc_init_once);
}

long long oo_cap_grant_alloc(void) {
  oo_alloc_init();
  return g_tok_alloc;
}

void oo_cap_require_alloc(long long got, const char *op) {
  oo_alloc_init();
  if (got != g_tok_alloc) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n",
            op ? op : "alloc");
    exit(1);
  }
}

int oo_cap_is_alloc(long long got) {
  oo_alloc_init();
  return got == g_tok_alloc;
}

/* CHANGE B: quota counter is shared process state. Wrap the read-modify-
 * write of oo_list_ambient_quota in a mutex so concurrent alloc_bytes /
 * free_bytes callers cannot lose updates. The mutex lives in chs_rt_list.c
 * (where the ambient-quota state is owned); declared extern here. */
extern pthread_mutex_t g_quota_mu;
extern long long oo_list_ambient_quota;
extern long long oo_list_ambient_bytes;
extern void oo_list_quota_init_public(void);

/* Per-raise ceiling for oo_alloc_bytes (bytes). Related to ambient List quota
 * (default 64MiB in chs_rt_list; raised process-locally via this helper).
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

long long oo_alloc(long long size) {
  if (size <= 0 || size > OO_ALLOC_BYTES_MAX) return 0;
  oo_list_quota_init_public();
  size_t total_sz = sizeof(OoRawAllocHeader) + (size_t)size;
  if (total_sz % 16 != 0) total_sz += 16 - (total_sz % 16);

  pthread_mutex_lock(&g_quota_mu);
  if (oo_list_ambient_bytes + (long long)total_sz > oo_list_ambient_quota) {
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

void oo_free(long long ptr) {
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

void (oo_write_int)(long long ptr, long long offset, long long val) {
  if (!ptr) { fprintf(stderr, "ERR\tmem\tnull pointer dereference in oo_write_int\n"); exit(1); }
  if (offset < 0) { fprintf(stderr, "ERR\tmem\tnegative offset in oo_write_int\n"); exit(1); }
  OoRawAllocHeader *hdr = (OoRawAllocHeader *)((char *)(uintptr_t)ptr - sizeof(OoRawAllocHeader));
  if (hdr->magic == OO_RAW_ALLOC_MAGIC && (size_t)offset + sizeof(long long) > hdr->capacity) {
    fprintf(stderr, "ERR\tmem\tout of bounds write in oo_write_int\n");
    exit(1);
  }
  long long *dest = (long long *)((char *)(uintptr_t)ptr + offset);
  *dest = val;
}

long long (oo_read_int)(long long ptr, long long offset) {
  if (!ptr) { fprintf(stderr, "ERR\tmem\tnull pointer dereference in oo_read_int\n"); exit(1); }
  if (offset < 0) { fprintf(stderr, "ERR\tmem\tnegative offset in oo_read_int\n"); exit(1); }
  OoRawAllocHeader *hdr = (OoRawAllocHeader *)((char *)(uintptr_t)ptr - sizeof(OoRawAllocHeader));
  if (hdr->magic == OO_RAW_ALLOC_MAGIC && (size_t)offset + sizeof(long long) > hdr->capacity) {
    fprintf(stderr, "ERR\tmem\tout of bounds read in oo_read_int\n");
    exit(1);
  }
  long long *src = (long long *)((char *)(uintptr_t)ptr + offset);
  return *src;
}

long long heap_alloc_test(void) {
  long long p = oo_alloc(32);
  if (!p) { fprintf(stderr, "ERR\tmem\theap_alloc_test failed\n"); exit(1); }
  (oo_write_int)(p, 0, 77);
  (oo_write_int)(p, 8, 88);
  long long v0 = (oo_read_int)(p, 0);
  long long v1 = (oo_read_int)(p, 8);
  if (v0 != 77 || v1 != 88) {
    fprintf(stderr, "ERR\tmem\theap_alloc_test data corruption (v0=%lld, v1=%lld)\n", v0, v1);
    oo_free(p);
    exit(1);
  }
  oo_free(p);
  return 77;
}

