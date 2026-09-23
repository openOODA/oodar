/* Dedicated intern for 0..8191. pack_skip/pack_tok call to_string on
 * line, col, and byte index every lexer step. Hash-slice intern collides. */
#include "../../oodar.h"
#include <pthread.h>

#define OO_INT_INTERN 8192
typedef struct {
    OoStrHeader hdr;
    char data[8];
} OoIntEntry;

static OoIntEntry g_int[OO_INT_INTERN];
/* Zero len = entry not yet built (every interned uint has len >= 1, so 0
 * is a sound uninit sentinel). Bulk pthread_once init ran 8192 snprintfs
 * on first use even when the caller needed one value; per-entry lazy init
 * builds only the entries actually requested. Same bytes, same flags. */
static unsigned char g_int_len[OO_INT_INTERN];
static pthread_mutex_t g_int_mu = PTHREAD_MUTEX_INITIALIZER;

static inline void g_int_build(int n) {
    g_int[n].hdr.ref_count = 1;
    g_int[n].hdr.flags = OO_FLAG_STATIC;
    int w = snprintf(g_int[n].data, sizeof(g_int[n].data), "%d", n);
    g_int_len[n] = (unsigned char)(w > 0 ? w : 0);
}

OoStr oo_int_intern(long long n) {
    OoStr r;
    if (n >= 0 && n < OO_INT_INTERN) {
        if (g_int_len[(int)n] == 0) {
            pthread_mutex_lock(&g_int_mu);
            if (g_int_len[(int)n] == 0) g_int_build((int)n);
            pthread_mutex_unlock(&g_int_mu);
        }
        r.len = (long long)g_int_len[(int)n];
        r.data = g_int[(int)n].data;
        return r;
    }
    {
        char buf[32];
        int w = snprintf(buf, sizeof(buf), "%lld", n);
        if (w < 0) {
            abort();
        }
        return oo_str_intern_bytes(buf, (long long)w);
    }
}

