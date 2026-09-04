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
static unsigned char g_int_len[OO_INT_INTERN];
static pthread_once_t g_int_once = PTHREAD_ONCE_INIT;

static void g_int_init(void) {
    int n;
    for (n = 0; n < OO_INT_INTERN; n++) {
        g_int[n].hdr.ref_count = 1;
        g_int[n].hdr.flags = OO_FLAG_STATIC;
        int w = snprintf(g_int[n].data, sizeof(g_int[n].data), "%d", n);
        g_int_len[n] = (unsigned char)(w > 0 ? w : 0);
    }
}

OoStr oo_int_intern(long long n) {
    OoStr r;
    if (n >= 0 && n < OO_INT_INTERN) {
        pthread_once(&g_int_once, g_int_init);
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

