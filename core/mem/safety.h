/* oodar/core/mem/safety.h — Debug-mode memory safety shims.
 *
 * When built with `-DOODAR_MEMSAFE=1`, every public `oo_*` entry
 * point adds bounds + null + refcount checks at function entry.
 * Production builds (no -DOODAR_MEMSAFE) have these as no-ops
 * (single `if (0)` the compiler removes).
 *
 * Trade-off: ~5-10% perf cost in memsafe mode for production-grade
 * hostile-input protection. Use this build for sandbox / fuzz /
 * CI environments, not for hot-path production.
 *
 * Pattern:
 *
 *   #include "core/mem/safety.h"
 *   OoResS oo_read_file(long long cap, OoStr path) {
 *     OO_ENTRY();
 *     OO_NONNULL(path.data);
 *     OO_BOUNDS(path.len >= 0);
 *     ...
 *   }
 *
 * Each macro is a no-op when OODAR_MEMSAFE is unset. When set, the
 * macros call `oo_safety_fail(...)` which prints a diagnostic and
 * aborts — same fail-closed posture as cap=0 rejection.
 */

#ifndef OODAR_SAFETY_H
#define OODAR_SAFETY_H

#include <stdio.h>
#include <stdlib.h>

#ifdef OODAR_MEMSAFE

/* Debug-mode fail-closed. The format mirrors the cap-system ERR
 * format so log parsers can recognize both kinds of denial. */
OO_COLD static void oo_safety_fail(const char *file, int line,
                                    const char *func, const char *check,
                                    const char *detail) {
  fprintf(stderr,
          "ERR\tsafety\t%s:%d %s: %s%s%s\n",
          file, line, func, check,
          detail ? ": " : "",
          detail ? detail : "");
  abort();
}

#define OO_ENTRY()                                                          \
  do { /* sentinel — call at function entry to anchor the stack trace */   \
  } while (0)

#define OO_NONNULL(cond)                                                    \
  do {                                                                      \
    if (!(cond)) {                                                          \
      oo_safety_fail(__FILE__, __LINE__, __func__, "non-null", #cond);     \
    }                                                                       \
  } while (0)

#define OO_BOUNDS(cond)                                                     \
  do {                                                                      \
    if (!(cond)) {                                                          \
      oo_safety_fail(__FILE__, __LINE__, __func__, "bounds", #cond);       \
    }                                                                       \
  } while (0)

#define OO_RANGE(idx, n)                                                    \
  do {                                                                      \
    long long _idx = (long long)(idx);                                      \
    long long _n = (long long)(n);                                          \
    if (_idx < 0 || _idx >= _n) {                                           \
      oo_safety_fail(__FILE__, __LINE__, __func__,                          \
                     "range", #idx " vs " #n);                               \
    }                                                                       \
  } while (0)

#define OO_REFCNT_OK(hdr_ptr)                                               \
  do {                                                                      \
    OoStrHeader *_h = (hdr_ptr);                                            \
    uint32_t _rc = __atomic_load_n(&_h->ref_count, __ATOMIC_ACQUIRE);      \
    uint32_t _fl = __atomic_load_n(&_h->flags, __ATOMIC_ACQUIRE);          \
    if (_rc == 0 || _rc == UINT32_MAX ||                                    \
        (_fl & OO_FLAG_STATIC) || _fl == 0xFFFFFFFFu ||                     \
        _rc > 1000000u) {                                                   \
      oo_safety_fail(__FILE__, __LINE__, __func__,                          \
                     "refcount", "header corruption");                      \
    }                                                                       \
  } while (0)

#define OO_FAIL(check, detail)                                              \
  do {                                                                      \
    oo_safety_fail(__FILE__, __LINE__, __func__, (check), (detail));       \
  } while (0)

#else /* !OODAR_MEMSAFE — production build, all no-ops */

/* Stubs that the compiler folds to nothing. `if (0)` with side
 * effect-free condition; the unused-variable diagnostic would fire
 * for some macros, so we cast to void to silence. */
static inline void oo_safety_noop(void) {}

#define OO_ENTRY()                ((void)0)
#define OO_NONNULL(cond)          ((void)0)
#define OO_BOUNDS(cond)           ((void)0)
#define OO_RANGE(idx, n)          ((void)0)
#define OO_REFCNT_OK(hdr_ptr)     ((void)0)
#define OO_FAIL(check, detail)    ((void)0)

#endif /* OODAR_MEMSAFE */

#endif /* OODAR_SAFETY_H */
