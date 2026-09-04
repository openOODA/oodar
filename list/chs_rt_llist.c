/* Nested List[List[T]] (2D), List[List[List[T]]] (3D), List[List[List[List[T]]]] (4D).
 * Compressed via X-macro over the 3 element types: Int (I), String (S), Float (F).
 * All three element-type variants share the same control-block / quota / push / get logic;
 * only the element type and its retain/release functions differ. */

#include "chs_rt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Element type table: 2D List[List[T]]; 3D and 4D reference the 2D and 3D entries by name. */
#define LL_ELEM_TABLE(X) \
  X(I, OoIList, oo_ilist, sizeof(OoIList))  \
  X(S, OoSList, oo_slist, sizeof(OoSList))  \
  X(F, OoFList, oo_flist, sizeof(OoFList))

/* --- 2D: List[List[T]] (OoLL_*) -------------------------------------- */

#define LL_2D_FNS(SFX, ETYPE, EFAM, ESZ)                                  \
  void oo_ll_##SFX##_retain(OoLL_##SFX l) {                               \
    if (!l.data) return;                                                  \
    OoListHeader *hdr = ((OoListHeader *)l.data) - 1;                     \
    uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);     \
    uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);         \
    if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;                  \
    while (rc > 0 && rc < UINT32_MAX) {                                   \
      if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1,    \
                                      __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return; \
      rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);            \
      fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);                \
      if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;                \
    }                                                                     \
  }                                                                       \
  void oo_ll_##SFX##_release(OoLL_##SFX l) {                              \
    if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;                    \
    OoListHeader *hdr = ((OoListHeader *)l.data) - 1;                     \
    uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL); \
    if (prev == 1) {                                                      \
      for (long long i = 0; i < l.len; i++) EFAM##_release(l.data[i]);   \
      __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);      \
      __atomic_thread_fence(__ATOMIC_RELEASE);                            \
      pthread_mutex_lock(&g_quota_mu);                                    \
      oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, ESZ);           \
      pthread_mutex_unlock(&g_quota_mu);                                  \
      oo_payload_free(l.data);                                            \
    }                                                                     \
  }                                                                       \
  OoLL_##SFX oo_ll_##SFX##_new(void) { OoLL_##SFX l = {NULL, 0, 0}; return l; } \
  OoLL_##SFX oo_ll_##SFX##_push(OoLL_##SFX l, ETYPE v) {                 \
    OoLL_##SFX n;                                                         \
    long long ncap = l.cap ? l.cap : 8;                                   \
    if (l.data && l.len < l.cap && oo_list_owned(l.data)) {               \
      l.data[l.len] = v; EFAM##_retain(v); l.len = l.len + 1;             \
      oo_ll_##SFX##_retain(l); return l;                                  \
    }                                                                     \
    while (ncap < l.len + 1) ncap *= 2;                                   \
    n.data = (ETYPE *)oo_list_alloc_payload(ESZ, (size_t)ncap);           \
    if (l.data && l.len > 0) {                                            \
      memcpy(n.data, l.data, (size_t)l.len * ESZ);                        \
      for (long long i = 0; i < l.len; i++) EFAM##_retain(n.data[i]);     \
    }                                                                     \
    n.data[l.len] = v; EFAM##_retain(v); n.len = l.len + 1; n.cap = ncap; \
    { OoListHeader *hdr = ((OoListHeader *)n.data) - 1;                   \
      __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }          \
    return n;                                                             \
  }                                                                       \
  ETYPE oo_ll_##SFX##_get(OoLL_##SFX l, long long i) {                    \
    ETYPE r;                                                              \
    oo_ll_##SFX##_retain(l);                                              \
    if (i < 0 || i >= l.len) {                                            \
      oo_ll_##SFX##_release(l);                                           \
      fprintf(stderr, "ERR\tll_" #SFX "_get OOB\n"); exit(1);             \
    }                                                                     \
    EFAM##_retain(l.data[i]); r = l.data[i];                              \
    oo_ll_##SFX##_release(l); return r;                                   \
  }                                                                       \
  long long oo_ll_##SFX##_len(OoLL_##SFX l) { return l.len; }             \
  OoLL_##SFX oo_ll_##SFX##_set(OoLL_##SFX l, long long i, ETYPE v) {     \
    OoLL_##SFX n; long long ncap; long long j;                            \
    if (i < 0 || i >= l.len) { fprintf(stderr, "ERR\tll_" #SFX "_set OOB\n"); exit(1); } \
    if (l.data && oo_list_owned(l.data)) {                                \
      ETYPE old = l.data[i]; l.data[i] = v;                               \
      EFAM##_retain(v); EFAM##_release(old);                              \
      oo_ll_##SFX##_retain(l); return l;                                  \
    }                                                                     \
    ncap = l.cap ? l.cap : l.len;                                         \
    n.data = (ETYPE *)oo_list_alloc_payload(ESZ, (size_t)ncap);           \
    if (l.data && l.len > 0) {                                            \
      memcpy(n.data, l.data, (size_t)l.len * ESZ);                        \
      for (j = 0; j < l.len; j++) if (j != i) EFAM##_retain(n.data[j]);   \
    }                                                                     \
    n.data[i] = v; EFAM##_retain(v); n.len = l.len; n.cap = ncap;         \
    { OoListHeader *hdr = ((OoListHeader *)n.data) - 1;                   \
      __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }          \
    return n;                                                             \
  }

LL_ELEM_TABLE(LL_2D_FNS)
#undef LL_2D_FNS

/* --- 3D: List[List[List[T]]] (OoLLL_*) --------------------------------- */

#define LL_3D_FNS(SFX, ETYPE, EFAM, ESZ)                                  \
  void oo_lll_##SFX##_retain(OoLLL_##SFX l) {                             \
    if (!l.data) return;                                                  \
    OoListHeader *hdr = ((OoListHeader *)l.data) - 1;                     \
    uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);     \
    uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);         \
    if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;                  \
    while (rc > 0 && rc < UINT32_MAX) {                                   \
      if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1,    \
                                      __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return; \
      rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);            \
      fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);                \
      if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;                \
    }                                                                     \
  }                                                                       \
  void oo_lll_##SFX##_release(OoLLL_##SFX l) {                            \
    if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;                    \
    OoListHeader *hdr = ((OoListHeader *)l.data) - 1;                     \
    uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL); \
    if (prev == 1) {                                                      \
      for (long long i = 0; i < l.len; i++) oo_ll_##SFX##_release(l.data[i]); \
      __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);      \
      __atomic_thread_fence(__ATOMIC_RELEASE);                            \
      pthread_mutex_lock(&g_quota_mu);                                    \
      oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoLL_##SFX)); \
      pthread_mutex_unlock(&g_quota_mu);                                  \
      oo_payload_free(l.data);                                            \
    }                                                                     \
  }                                                                       \
  OoLLL_##SFX oo_lll_##SFX##_new(void) { OoLLL_##SFX l = {NULL, 0, 0}; return l; } \
  OoLLL_##SFX oo_lll_##SFX##_push(OoLLL_##SFX l, OoLL_##SFX v) {          \
    OoLLL_##SFX n;                                                        \
    long long ncap = l.cap ? l.cap : 8;                                   \
    if (l.data && l.len < l.cap && oo_list_owned(l.data)) {               \
      l.data[l.len] = v; oo_ll_##SFX##_retain(v); l.len = l.len + 1;      \
      oo_lll_##SFX##_retain(l); return l;                                 \
    }                                                                     \
    while (ncap < l.len + 1) ncap *= 2;                                   \
    n.data = (OoLL_##SFX *)oo_list_alloc_payload(sizeof(OoLL_##SFX), (size_t)ncap); \
    if (l.data && l.len > 0) {                                            \
      memcpy(n.data, l.data, (size_t)l.len * sizeof(OoLL_##SFX));         \
      for (long long i = 0; i < l.len; i++) oo_ll_##SFX##_retain(n.data[i]); \
    }                                                                     \
    n.data[l.len] = v; oo_ll_##SFX##_retain(v); n.len = l.len + 1; n.cap = ncap; \
    { OoListHeader *hdr = ((OoListHeader *)n.data) - 1;                   \
      __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }          \
    return n;                                                             \
  }                                                                       \
  OoLL_##SFX oo_lll_##SFX##_get(OoLLL_##SFX l, long long i) {             \
    OoLL_##SFX r;                                                         \
    oo_lll_##SFX##_retain(l);                                             \
    if (i < 0 || i >= l.len) {                                            \
      oo_lll_##SFX##_release(l);                                          \
      fprintf(stderr, "ERR\tlll_" #SFX "_get OOB\n"); exit(1);            \
    }                                                                     \
    oo_ll_##SFX##_retain(l.data[i]); r = l.data[i];                       \
    oo_lll_##SFX##_release(l); return r;                                  \
  }                                                                       \
  long long oo_lll_##SFX##_len(OoLLL_##SFX l) { return l.len; }

LL_ELEM_TABLE(LL_3D_FNS)
#undef LL_3D_FNS

/* --- 4D: List[List[List[List[T]]]] (OoLLLL_*) --------------------------- */

#define LL_4D_FNS(SFX, ETYPE, EFAM, ESZ)                                  \
  void oo_llll_##SFX##_retain(OoLLLL_##SFX l) {                           \
    if (!l.data) return;                                                  \
    OoListHeader *hdr = ((OoListHeader *)l.data) - 1;                     \
    uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);     \
    uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);         \
    if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;                  \
    while (rc > 0 && rc < UINT32_MAX) {                                   \
      if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1,    \
                                      __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return; \
      rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);            \
      fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);                \
      if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;                \
    }                                                                     \
  }                                                                       \
  void oo_llll_##SFX##_release(OoLLLL_##SFX l) {                          \
    if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;                    \
    OoListHeader *hdr = ((OoListHeader *)l.data) - 1;                     \
    uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL); \
    if (prev == 1) {                                                      \
      for (long long i = 0; i < l.len; i++) oo_lll_##SFX##_release(l.data[i]); \
      __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);      \
      __atomic_thread_fence(__ATOMIC_RELEASE);                            \
      pthread_mutex_lock(&g_quota_mu);                                    \
      oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoLLL_##SFX)); \
      pthread_mutex_unlock(&g_quota_mu);                                  \
      oo_payload_free(l.data);                                            \
    }                                                                     \
  }                                                                       \
  OoLLLL_##SFX oo_llll_##SFX##_new(void) { OoLLLL_##SFX l = {NULL, 0, 0}; return l; } \
  OoLLLL_##SFX oo_llll_##SFX##_push(OoLLLL_##SFX l, OoLLL_##SFX v) {      \
    OoLLLL_##SFX n;                                                       \
    long long ncap = l.cap ? l.cap : 8;                                   \
    if (l.data && l.len < l.cap && oo_list_owned(l.data)) {               \
      l.data[l.len] = v; oo_lll_##SFX##_retain(v); l.len = l.len + 1;     \
      oo_llll_##SFX##_retain(l); return l;                                \
    }                                                                     \
    while (ncap < l.len + 1) ncap *= 2;                                   \
    n.data = (OoLLL_##SFX *)oo_list_alloc_payload(sizeof(OoLLL_##SFX), (size_t)ncap); \
    if (l.data && l.len > 0) {                                            \
      memcpy(n.data, l.data, (size_t)l.len * sizeof(OoLLL_##SFX));        \
      for (long long i = 0; i < l.len; i++) oo_lll_##SFX##_retain(n.data[i]); \
    }                                                                     \
    n.data[l.len] = v; oo_lll_##SFX##_retain(v); n.len = l.len + 1; n.cap = ncap; \
    { OoListHeader *hdr = ((OoListHeader *)n.data) - 1;                   \
      __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }          \
    return n;                                                             \
  }                                                                       \
  OoLLL_##SFX oo_llll_##SFX##_get(OoLLLL_##SFX l, long long i) {         \
    OoLLL_##SFX r;                                                        \
    oo_llll_##SFX##_retain(l);                                            \
    if (i < 0 || i >= l.len) {                                            \
      oo_llll_##SFX##_release(l);                                         \
      fprintf(stderr, "ERR\tllll_" #SFX "_get OOB\n"); exit(1);           \
    }                                                                     \
    oo_lll_##SFX##_retain(l.data[i]); r = l.data[i];                      \
    oo_llll_##SFX##_release(l); return r;                                 \
  }                                                                       \
  long long oo_llll_##SFX##_len(OoLLLL_##SFX l) { return l.len; }

LL_ELEM_TABLE(LL_4D_FNS)
#undef LL_4D_FNS
