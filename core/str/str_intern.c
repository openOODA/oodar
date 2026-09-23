/* One-char, short-string static slab, and multi-byte string interning pool.
 * STATIC flag makes retain/release no-ops (oo_str_hdr_ok rejects STATIC). */
#include "../../oodar.h"
#include <pthread.h>

typedef struct {
    OoStrHeader hdr;
    char data[8];
} OoAsciiEntry;

#define OO_A1(i) { { 1, (i < 128 ? (OO_FLAG_STATIC | OO_FLAG_ASCII) : OO_FLAG_STATIC) }, { (char)(i), 0 } }
#define OO_A4(i) OO_A1(i), OO_A1((i)+1), OO_A1((i)+2), OO_A1((i)+3)
#define OO_A16(i) OO_A4(i), OO_A4((i)+4), OO_A4((i)+8), OO_A4((i)+12)
#define OO_A64(i) OO_A16(i), OO_A16((i)+16), OO_A16((i)+32), OO_A16((i)+48)
static OoAsciiEntry g_ascii[256] = { OO_A64(0), OO_A64(64), OO_A64(128), OO_A64(192) };

OoStr oo_str_ascii_intern(unsigned char c) {
    OoStr r;
    r.len = 1;
    r.data = g_ascii[c].data;
    return r;
}

#define OO_SLAB_CAP 16384
#define OO_SLAB_HASH_SIZE 32768
#define OO_SLAB_HASH_MASK (OO_SLAB_HASH_SIZE - 1)

typedef struct {
    OoStrHeader hdr;
    char data[16];
} OoStrSlabEntry;

typedef struct {
    OoStrSlabEntry entries[OO_SLAB_CAP];
    uint16_t hash_tab[OO_SLAB_HASH_SIZE];
    size_t count;
} OoStrSlabPool;

/* Lazy per-thread slab: a static pool costs ~459 KB of zeroed TLS per
 * thread at startup (112 minor faults before main even when unused).
 * The pointer is 8 bytes of TLS; the pool is calloc'd on first short
 * intern, so untouched processes pay zero faults. calloc zeroes, matching
 * the old .tbss zero-init exactly. Same cap, same probe order. */
static __thread OoStrSlabPool *g_tls_slab_ptr;

static inline OoStrSlabPool *oo_tls_slab(void) {
    OoStrSlabPool *s = g_tls_slab_ptr;
    if (!s) {
        s = (OoStrSlabPool *)calloc(1, sizeof(OoStrSlabPool));
        if (!s) abort();
        g_tls_slab_ptr = s;
    }
    return s;
}

typedef struct OoInternNode {
    struct OoInternNode *next;
    long long len;
    OoStrHeader hdr;
} OoInternNode;

#define OO_INTERN_BUCKETS 4096
static OoInternNode *g_intern_table[OO_INTERN_BUCKETS];
static pthread_mutex_t g_intern_mu = PTHREAD_MUTEX_INITIALIZER;

static OoAsciiEntry g_empty_intern = { .hdr = { 1, OO_FLAG_STATIC | OO_FLAG_ASCII }, .data = "" };

OoStr oo_str_intern_bytes(const char *p, long long n) {
    if (!p || n <= 0) return (OoStr){ .data = g_empty_intern.data, .len = 0 };
    if (n == 1) return oo_str_ascii_intern((unsigned char)p[0]);
    unsigned h = 2166136261u;
    for (long long i = 0; i < n; i++) h = (h ^ (unsigned char)p[i]) * 16777619u;
    if (n <= 15) {
        OoStrSlabPool *s = oo_tls_slab();
        unsigned slot = h & OO_SLAB_HASH_MASK, step = 1;
        while (s->hash_tab[slot] != 0) {
            uint16_t idx = s->hash_tab[slot] - 1;
            if (s->entries[idx].data[n] == '\0' &&
                memcmp(s->entries[idx].data, p, (size_t)n) == 0) {
                return (OoStr){ .data = s->entries[idx].data, .len = n };
            }
            slot = (slot + step++) & OO_SLAB_HASH_MASK;
        }
        if (s->count < OO_SLAB_CAP) {
            uint16_t idx = (uint16_t)s->count++;
            unsigned char or_b = 0;
            for (long long k = 0; k < n; k++) or_b |= (unsigned char)p[k];
            s->entries[idx].hdr.ref_count = 1;
            s->entries[idx].hdr.flags = OO_FLAG_STATIC | ((or_b & 0x80) ? 0 : OO_FLAG_ASCII);
            memcpy(s->entries[idx].data, p, (size_t)n);
            s->entries[idx].data[n] = '\0';
            s->hash_tab[slot] = idx + 1;
            return (OoStr){ .data = s->entries[idx].data, .len = n };
        }
    }
    unsigned slot = h % OO_INTERN_BUCKETS;
    for (OoInternNode *node = __atomic_load_n(&g_intern_table[slot], __ATOMIC_ACQUIRE);
         node != NULL;
         node = __atomic_load_n(&node->next, __ATOMIC_ACQUIRE)) {
        if (node->len == n && memcmp((char *)(node + 1), p, (size_t)n) == 0) {
            return (OoStr){ .data = (char *)(node + 1), .len = n };
        }
    }
    pthread_mutex_lock(&g_intern_mu);
    for (OoInternNode *node = g_intern_table[slot]; node != NULL; node = node->next) {
        if (node->len == n && memcmp((char *)(node + 1), p, (size_t)n) == 0) {
            char *data = (char *)(node + 1);
            pthread_mutex_unlock(&g_intern_mu);
            return (OoStr){ .data = data, .len = n };
        }
    }
    OoInternNode *node = (OoInternNode *)malloc(sizeof(OoInternNode) + (size_t)n + 1);
    if (!node) abort();
    unsigned char or_b = 0;
    for (long long k = 0; k < n; k++) or_b |= (unsigned char)p[k];
    node->len = n;
    node->hdr.ref_count = 1;
    node->hdr.flags = OO_FLAG_STATIC | ((or_b & 0x80) ? 0 : OO_FLAG_ASCII);
    char *data = (char *)(node + 1);
    memcpy(data, p, (size_t)n);
    data[n] = 0;
    node->next = g_intern_table[slot];
    __atomic_store_n(&g_intern_table[slot], node, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_intern_mu);
    return (OoStr){ .data = data, .len = n };
}

/* Public oo_byte_slice: slab fast path for <=15-byte results, heap core above.
 * oo_byte_slice_orig lives in str_ops.c (no macro rename: each TU owns one
 * symbol, so umbrella and per-file builds both link without duplicates). */
OoStr oo_byte_slice_orig(OoStr s, long long start, long long end);
OoStr oo_byte_slice(OoStr s, long long start, long long end) {
    if (!s.data || s.len < 0) return oo_str_intern_bytes("", 0);
    if (start < 0) start = 0;
    if (end > s.len) end = s.len;
    if (start > end || start >= s.len) return oo_str_intern_bytes("", 0);
    long long rlen = end - start;
    if (rlen <= 15) return oo_str_intern_bytes(s.data + start, rlen);
    return oo_byte_slice_orig(s, start, end);
}
