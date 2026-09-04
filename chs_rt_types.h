#ifndef CHS_RT_TYPES_H
#define CHS_RT_TYPES_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>

long long oo_monotonic_us(void);
#define OO_FLAG_STATIC 1

typedef struct {
  uint32_t ref_count;
  uint32_t flags;
} OoStrHeader;

typedef struct {
  uint32_t ref_count;
  uint32_t flags;
} OoListHeader;

typedef struct {
  char *data;
  long long len;
} OoStr;

typedef struct {
  long long *data;
  long long len;
  long long cap;
} OoIList;

typedef struct {
  OoStr *data;
  long long len;
  long long cap;
} OoSList;

typedef struct {
  double *data;
  long long len;
  long long cap;
} OoFList;

typedef struct {
  int ok;
  OoStr val;
} OoResS;

typedef struct {
  int ok;
  OoStr err;
} OoResV;

typedef struct { int ok; long long val; OoStr err; } OoResI;
typedef struct { int ok; int val; OoStr err; } OoResB;
typedef struct { int ok; double val; OoStr err; } OoResF;
typedef struct { int ok; OoIList val; OoStr err; } OoResLI;
typedef struct { int ok; OoSList val; OoStr err; } OoResLS;
typedef struct { int ok; OoFList val; OoStr err; } OoResLF;

typedef struct { OoIList *data; long long len; long long cap; } OoLL_I;
typedef struct { OoSList *data; long long len; long long cap; } OoLL_S;
typedef struct { OoFList *data; long long len; long long cap; } OoLL_F;
typedef struct { OoLL_I *data; long long len; long long cap; } OoLLL_I;
typedef struct { OoLL_S *data; long long len; long long cap; } OoLLL_S;
typedef struct { OoLL_F *data; long long len; long long cap; } OoLLL_F;
typedef struct { OoLLL_I *data; long long len; long long cap; } OoLLLL_I;
typedef struct { OoLLL_S *data; long long len; long long cap; } OoLLLL_S;
typedef struct { OoLLL_F *data; long long len; long long cap; } OoLLLL_F;

typedef struct { int ok; int has_val; long long val; OoStr err; } OoResO_I;
typedef struct { int ok; int has_val; OoStr val; OoStr err; } OoResO_S;
typedef struct { int ok; int has_val; int val; OoStr err; } OoResO_B;
typedef struct { int ok; int has_val; double val; OoStr err; } OoResO_F;
typedef struct { int ok; int has_val; OoIList val; OoStr err; } OoResO_LI;
typedef struct { int ok; int has_val; OoSList val; OoStr err; } OoResO_LS;
typedef struct { int ok; int has_val; OoFList val; OoStr err; } OoResO_LF;
typedef struct { int ok; int has_val; OoLLL_I val; OoStr err; } OoResO_LLL_I;

typedef struct OoClosure {
    void *fn;
    void *env;
    void (*dtor)(void*);
} OoClosure;

typedef struct OoFlatEnvHeader {
    uint32_t ref_count;
    uint32_t flags;
    void (*dtor)(void*);
} OoFlatEnvHeader;

OoClosure oo_closure_stack(void *fn, void *stack_env);
OoClosure oo_closure_heap_create(void *fn, size_t env_size, const void *env_data, void (*dtor)(void*));
void oo_closure_retain(OoClosure clo);
void oo_closure_release(OoClosure clo);
void *oo_closure_flat_alloc(size_t env_payload_size, void (*dtor)(void*));
void oo_closure_flat_retain(void *env);
void oo_closure_flat_release(void *env);


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

extern long long oo_list_ambient_quota;
extern long long oo_list_ambient_bytes;
void oo_list_quota_init_public(void);
char *oo_str_alloc_payload(size_t len);
void *oo_list_alloc_payload(size_t elem_size, size_t cap);
void oo_list_quota_release_bytes(long long cap, size_t elem_size);
void *oo_payload_alloc(size_t hdr_sz, size_t payload_sz);
void oo_payload_free(void *payload);
int oo_payload_aligned(const void *p);
long long oo_list_block_bytes(long long cap, size_t elem);

void oo_str_retain(OoStr s);
void oo_str_release(OoStr s);
void oo_ilist_retain(OoIList l);
void oo_ilist_release(OoIList l);
void oo_slist_retain(OoSList l);
void oo_slist_release(OoSList l);
void oo_flist_retain(OoFList l);
void oo_flist_release(OoFList l);

#ifndef OO_RETAIN_OoResS
#define OO_RETAIN_OoResS
static inline void oo_retain_OoResS(OoResS v) { if (v.ok) oo_str_retain(v.val); }
#endif
#ifndef OO_RELEASE_OoResS
#define OO_RELEASE_OoResS
static inline void oo_release_OoResS(OoResS v) { if (v.ok) oo_str_release(v.val); }
#endif
#ifndef OO_RETAIN_OoResV
#define OO_RETAIN_OoResV
static inline void oo_retain_OoResV(OoResV v) { if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResV
#define OO_RELEASE_OoResV
static inline void oo_release_OoResV(OoResV v) { if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResI
#define OO_RETAIN_OoResI
static inline void oo_retain_OoResI(OoResI v) { if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResI
#define OO_RELEASE_OoResI
static inline void oo_release_OoResI(OoResI v) { if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResB
#define OO_RETAIN_OoResB
static inline void oo_retain_OoResB(OoResB v) { if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResB
#define OO_RELEASE_OoResB
static inline void oo_release_OoResB(OoResB v) { if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResF
#define OO_RETAIN_OoResF
static inline void oo_retain_OoResF(OoResF v) { if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResF
#define OO_RELEASE_OoResF
static inline void oo_release_OoResF(OoResF v) { if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResLI
#define OO_RETAIN_OoResLI
static inline void oo_retain_OoResLI(OoResLI v) { if (v.ok) oo_ilist_retain(v.val); else oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResLI
#define OO_RELEASE_OoResLI
static inline void oo_release_OoResLI(OoResLI v) { if (v.ok) oo_ilist_release(v.val); else oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResLS
#define OO_RETAIN_OoResLS
static inline void oo_retain_OoResLS(OoResLS v) { if (v.ok) oo_slist_retain(v.val); else oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResLS
#define OO_RELEASE_OoResLS
static inline void oo_release_OoResLS(OoResLS v) { if (v.ok) oo_slist_release(v.val); else oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResLF
#define OO_RETAIN_OoResLF
static inline void oo_retain_OoResLF(OoResLF v) { if (v.ok) oo_flist_retain(v.val); else oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResLF
#define OO_RELEASE_OoResLF
static inline void oo_release_OoResLF(OoResLF v) { if (v.ok) oo_flist_release(v.val); else oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResO_I
#define OO_RETAIN_OoResO_I
static inline void oo_retain_OoResO_I(OoResO_I v) { if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResO_I
#define OO_RELEASE_OoResO_I
static inline void oo_release_OoResO_I(OoResO_I v) { if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResO_S
#define OO_RETAIN_OoResO_S
static inline void oo_retain_OoResO_S(OoResO_S v) { if (v.ok && v.has_val) oo_str_retain(v.val); else if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResO_S
#define OO_RELEASE_OoResO_S
static inline void oo_release_OoResO_S(OoResO_S v) { if (v.ok && v.has_val) oo_str_release(v.val); else if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResO_B
#define OO_RETAIN_OoResO_B
static inline void oo_retain_OoResO_B(OoResO_B v) { if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResO_B
#define OO_RELEASE_OoResO_B
static inline void oo_release_OoResO_B(OoResO_B v) { if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResO_F
#define OO_RETAIN_OoResO_F
static inline void oo_retain_OoResO_F(OoResO_F v) { if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResO_F
#define OO_RELEASE_OoResO_F
static inline void oo_release_OoResO_F(OoResO_F v) { if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResO_LI
#define OO_RETAIN_OoResO_LI
static inline void oo_retain_OoResO_LI(OoResO_LI v) { if (v.ok && v.has_val) oo_ilist_retain(v.val); else if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResO_LI
#define OO_RELEASE_OoResO_LI
static inline void oo_release_OoResO_LI(OoResO_LI v) { if (v.ok && v.has_val) oo_ilist_release(v.val); else if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResO_LS
#define OO_RETAIN_OoResO_LS
static inline void oo_retain_OoResO_LS(OoResO_LS v) { if (v.ok && v.has_val) oo_slist_retain(v.val); else if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResO_LS
#define OO_RELEASE_OoResO_LS
static inline void oo_release_OoResO_LS(OoResO_LS v) { if (v.ok && v.has_val) oo_slist_release(v.val); else if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResO_LF
#define OO_RETAIN_OoResO_LF
static inline void oo_retain_OoResO_LF(OoResO_LF v) { if (v.ok && v.has_val) oo_flist_retain(v.val); else if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResO_LF
#define OO_RELEASE_OoResO_LF
static inline void oo_release_OoResO_LF(OoResO_LF v) { if (v.ok && v.has_val) oo_flist_release(v.val); else if (!v.ok) oo_str_release(v.err); }
#endif
#ifndef OO_RETAIN_OoResO_LLL_I
#define OO_RETAIN_OoResO_LLL_I
static inline void oo_retain_OoResO_LLL_I(OoResO_LLL_I v) { if (v.ok && v.has_val) { if (v.val.data) { OoListHeader *hdr = ((OoListHeader *)v.val.data) - 1; uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE); while (rc > 0 && rc < UINT32_MAX) { if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) break; rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED); } } } else if (!v.ok) oo_str_retain(v.err); }
#endif
#ifndef OO_RELEASE_OoResO_LLL_I
#define OO_RELEASE_OoResO_LLL_I
static inline void oo_release_OoResO_LLL_I(OoResO_LLL_I v) { if (v.ok && v.has_val) oo_lll_I_release(v.val); else if (!v.ok) oo_str_release(v.err); }
#endif

OoStr oo_str_lit(const char *s);
OoStr oo_chr(long long cp);
OoStr oo_str_concat(OoStr a, OoStr b);
OoStr oo_str_concat_list(OoSList lst);
OoStr oo_str_concat_multi(int n, ...);
OoStr oo_str_xor_lit(const unsigned char *p, long long n, long long key);
OoStr oo_tok_line(OoStr kind, long long line, long long col, OoStr text);

long long oo_str_byte_len(OoStr s);
long long oo_chars_len(OoStr s);
OoStr oo_char_at(OoStr s, long long idx);
OoStr oo_str_ascii_intern(unsigned char c);
OoStr oo_str_intern_bytes(const char *p, long long n);
OoStr oo_str_slice(OoStr s, long long start, long long end);
int oo_char_is_digit(OoStr s);
int oo_char_is_alpha(OoStr s);
int oo_char_is_space(OoStr s);
OoStr oo_int_to_str(long long n);
OoStr oo_int_intern(long long n);
OoStr oo_str_trim(OoStr s);
OoStr oo_str_to_lowercase(OoStr s);
OoStr oo_str_to_uppercase(OoStr s);
int oo_str_eq(OoStr a, OoStr b);
int oo_str_contains(OoStr hay, OoStr needle);
int oo_str_starts_with(OoStr s, OoStr pre);
int oo_str_ends_with(OoStr s, OoStr suf);
long long oo_str_index_of(OoStr s, OoStr sub);
OoStr oo_str_repeat(OoStr s, long long n);

OoIList oo_ilist_new(void);
void oo_ilist_free(OoIList l);
OoIList oo_ilist_push(OoIList l, long long v);
long long oo_ilist_get(OoIList l, long long i);
long long oo_ilist_len(OoIList l);
OoIList oo_ilist_set(OoIList l, long long i, long long v);
int oo_ilist_eq(OoIList a, OoIList b);

OoSList oo_slist_new(void);
void oo_slist_free(OoSList l);
OoSList oo_slist_push(OoSList l, OoStr v);
OoStr oo_slist_get(OoSList l, long long i);
long long oo_slist_len(OoSList l);
OoSList oo_slist_set(OoSList l, long long i, OoStr v);
int oo_slist_eq(OoSList a, OoSList b);

OoFList oo_flist_new(void);
void oo_flist_free(OoFList l);
OoFList oo_flist_push(OoFList l, double v);
double oo_flist_get(OoFList l, long long i);
long long oo_flist_len(OoFList l);
OoFList oo_flist_set(OoFList l, long long i, double v);
int oo_flist_eq(OoFList a, OoFList b);

#ifndef OO_RETAIN_OoFList
#define OO_RETAIN_OoFList
static inline void oo_retain_OoFList(OoFList l) { oo_flist_retain(l); }
static inline void oo_release_OoFList(OoFList l) { oo_flist_release(l); }
#endif
#ifndef OO_RETAIN_OoIList
#define OO_RETAIN_OoIList
static inline void oo_retain_OoIList(OoIList l) { oo_ilist_retain(l); }
static inline void oo_release_OoIList(OoIList l) { oo_ilist_release(l); }
#endif
#ifndef OO_RETAIN_OoSList
#define OO_RETAIN_OoSList
static inline void oo_retain_OoSList(OoSList l) { oo_slist_retain(l); }
static inline void oo_release_OoSList(OoSList l) { oo_slist_release(l); }
#endif

#endif
