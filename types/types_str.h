#ifndef OODAR_TYPES_STR_H
#define OODAR_TYPES_STR_H
/* v2.3.0 split: OoStr, OoIList, OoSList, OoFList, headers, and the str/ilist/slist/flist
 * function decls and retain/release pairs. The atomic-header-based refcount
 * primitives live in core/list/list.c; this header only declares the public
 * surface. */
#include <stdint.h>

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

#endif
