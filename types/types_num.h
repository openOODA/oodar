#ifndef OODAR_TYPES_NUM_H
#define OODAR_TYPES_NUM_H
/* v2.3.0 split: nested-list types (OoLL_*, OoLLL_*, OoLLLL_*) and their
 * push/get/set/len/retain/release decls. The atomic-header refcount primitives
 * live in core/list/llist.c; this header only declares the public surface. */
#include "types_str.h"

typedef struct { OoIList *data; long long len; long long cap; } OoLL_I;
typedef struct { OoSList *data; long long len; long long cap; } OoLL_S;
typedef struct { OoFList *data; long long len; long long cap; } OoLL_F;
typedef struct { OoLL_I *data; long long len; long long cap; } OoLLL_I;
typedef struct { OoLL_S *data; long long len; long long cap; } OoLLL_S;
typedef struct { OoLL_F *data; long long len; long long cap; } OoLLL_F;
typedef struct { OoLLL_I *data; long long len; long long cap; } OoLLLL_I;
typedef struct { OoLLL_S *data; long long len; long long cap; } OoLLLL_S;
typedef struct { OoLLL_F *data; long long len; long long cap; } OoLLLL_F;

OoLL_I oo_ll_I_new(void);
OoLL_I oo_ll_I_push(OoLL_I l, OoIList v);
OoLL_I oo_ll_I_set(OoLL_I l, long long i, OoIList v);
OoIList oo_ll_I_get(OoLL_I l, long long i);
long long oo_ll_I_len(OoLL_I l);
void oo_ll_I_retain(OoLL_I l);
void oo_ll_I_release(OoLL_I l);

OoLL_S oo_ll_S_new(void);
OoLL_S oo_ll_S_push(OoLL_S l, OoSList v);
OoLL_S oo_ll_S_set(OoLL_S l, long long i, OoSList v);
OoSList oo_ll_S_get(OoLL_S l, long long i);
long long oo_ll_S_len(OoLL_S l);
void oo_ll_S_retain(OoLL_S l);
void oo_ll_S_release(OoLL_S l);

OoLL_F oo_ll_F_new(void);
OoLL_F oo_ll_F_push(OoLL_F l, OoFList v);
OoLL_F oo_ll_F_set(OoLL_F l, long long i, OoFList v);
OoFList oo_ll_F_get(OoLL_F l, long long i);
long long oo_ll_F_len(OoLL_F l);
void oo_ll_F_retain(OoLL_F l);
void oo_ll_F_release(OoLL_F l);

OoLLL_I oo_lll_I_new(void);
OoLLL_I oo_lll_I_push(OoLLL_I l, OoLL_I v);
OoLL_I oo_lll_I_get(OoLLL_I l, long long i);
long long oo_lll_I_len(OoLLL_I l);
void oo_lll_I_release(OoLLL_I l);

OoLLL_S oo_lll_S_new(void);
OoLLL_S oo_lll_S_push(OoLLL_S l, OoLL_S v);
OoLL_S oo_lll_S_get(OoLLL_S l, long long i);
long long oo_lll_S_len(OoLLL_S l);
void oo_lll_S_release(OoLLL_S l);

OoLLL_F oo_lll_F_new(void);
OoLLL_F oo_lll_F_push(OoLLL_F l, OoLL_F v);
OoLL_F oo_lll_F_get(OoLLL_F l, long long i);
long long oo_lll_F_len(OoLLL_F l);
void oo_lll_F_release(OoLLL_F l);

OoLLLL_I oo_llll_I_new(void);
OoLLLL_I oo_llll_I_push(OoLLLL_I l, OoLLL_I v);
OoLLL_I oo_llll_I_get(OoLLLL_I l, long long i);
long long oo_llll_I_len(OoLLLL_I l);
void oo_llll_I_retain(OoLLLL_I l);
void oo_llll_I_release(OoLLLL_I l);

OoLLLL_S oo_llll_S_new(void);
OoLLLL_S oo_llll_S_push(OoLLLL_S l, OoLLL_S v);
OoLLL_S oo_llll_S_get(OoLLLL_S l, long long i);
long long oo_llll_S_len(OoLLLL_S l);
void oo_llll_S_retain(OoLLLL_S l);
void oo_llll_S_release(OoLLLL_S l);

OoLLLL_F oo_llll_F_new(void);
OoLLLL_F oo_llll_F_push(OoLLLL_F l, OoLLL_F v);
OoLLL_F oo_llll_F_get(OoLLLL_F l, long long i);
long long oo_llll_F_len(OoLLLL_F l);
void oo_llll_F_retain(OoLLLL_F l);
void oo_llll_F_release(OoLLLL_F l);

#endif
