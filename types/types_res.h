#ifndef OODAR_TYPES_RES_H
#define OODAR_TYPES_RES_H
/* v2.3.0 split: result types (OoResS/V/I/B/F/LI/LS/LF and OoResO_*). Each
 * result type pairs an ok flag with a payload (val) and an err (OoStr) for
 * the failure path. The retain/release inlines drive the refcount
 * protocol; they live here as static inlines so callers do not need
 * to pull in the implementation TUs. */
#include "types_str.h"
#include "types_num.h"

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

typedef struct { int ok; int has_val; long long val; OoStr err; } OoResO_I;
typedef struct { int ok; int has_val; OoStr val; OoStr err; } OoResO_S;
typedef struct { int ok; int has_val; int val; OoStr err; } OoResO_B;
typedef struct { int ok; int has_val; double val; OoStr err; } OoResO_F;
typedef struct { int ok; int has_val; OoIList val; OoStr err; } OoResO_LI;
typedef struct { int ok; int has_val; OoSList val; OoStr err; } OoResO_LS;
typedef struct { int ok; int has_val; OoFList val; OoStr err; } OoResO_LF;
typedef struct { int ok; int has_val; OoLLL_I val; OoStr err; } OoResO_LLL_I;

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

#endif
