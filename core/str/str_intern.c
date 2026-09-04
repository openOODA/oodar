/* One-char and multi-byte string interning pool.
 * STATIC flag makes retain/release no-ops (oo_str_hdr_ok rejects STATIC). */
#include "../../oodar.h"
#include <pthread.h>

typedef struct {
    OoStrHeader hdr;
    char data[8];
} OoAsciiEntry;

static OoAsciiEntry g_ascii[256];
static pthread_once_t g_ascii_once = PTHREAD_ONCE_INIT;

static void g_ascii_init(void) {
    int i;
    for (i = 0; i < 256; i++) {
        g_ascii[i].hdr.ref_count = 1;
        g_ascii[i].hdr.flags = OO_FLAG_STATIC;
        g_ascii[i].data[0] = (char)i;
        g_ascii[i].data[1] = 0;
    }
}

OoStr oo_str_ascii_intern(unsigned char c) {
    OoStr r;
    pthread_once(&g_ascii_once, g_ascii_init);
    r.len = 1;
    r.data = g_ascii[c].data;
    return r;
}

typedef struct OoInternNode {
    struct OoInternNode *next;
    long long len;
    OoStrHeader hdr;
} OoInternNode;

#define OO_INTERN_BUCKETS 4096
static OoInternNode *g_intern_table[OO_INTERN_BUCKETS];
static pthread_mutex_t g_intern_mu = PTHREAD_MUTEX_INITIALIZER;

static OoAsciiEntry g_empty_intern = { .hdr = { 1, OO_FLAG_STATIC }, .data = "" };

OoStr oo_str_intern_bytes(const char *p, long long n) {
    unsigned h = 2166136261u;
    long long i;
    unsigned slot;
    OoStr r;
    if (n <= 0) {
        r.len = 0;
        r.data = g_empty_intern.data;
        return r;
    }
    if (n == 1) {
        return oo_str_ascii_intern((unsigned char)p[0]);
    }
    for (i = 0; i < n; i++) {
        h ^= (unsigned char)p[i];
        h *= 16777619u;
    }
    slot = h % OO_INTERN_BUCKETS;
    pthread_mutex_lock(&g_intern_mu);
    for (OoInternNode *node = g_intern_table[slot]; node != NULL; node = node->next) {
        if (node->len == n && memcmp((char *)(node + 1), p, (size_t)n) == 0) {
            char *data = (char *)(node + 1);
            pthread_mutex_unlock(&g_intern_mu);
            r.len = n;
            r.data = data;
            return r;
        }
    }
    OoInternNode *node = (OoInternNode *)malloc(sizeof(OoInternNode) + (size_t)n + 1);
    if (!node) abort();
    node->next = g_intern_table[slot];
    node->len = n;
    node->hdr.ref_count = 1;
    node->hdr.flags = OO_FLAG_STATIC;
    char *data = (char *)(node + 1);
    memcpy(data, p, (size_t)n);
    data[n] = 0;
    g_intern_table[slot] = node;
    pthread_mutex_unlock(&g_intern_mu);
    r.len = n;
    r.data = data;
    return r;
}

