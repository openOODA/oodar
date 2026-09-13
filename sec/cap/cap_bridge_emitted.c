/* runtime decls stripped; oo_retain_S/release_S shim added — see /home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo */
static inline void oo_retain_S(OoStr v) { oo_str_retain(v); }
static inline void oo_release_S(OoStr v) { oo_str_release(v); }
#line 1 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo"
#ifndef OO_FWD_OCapBridgeRecord
#define OO_FWD_OCapBridgeRecord
typedef struct OCapBridgeRecord OCapBridgeRecord;
static inline void oo_retain_OCapBridgeRecord(OCapBridgeRecord v);
static inline void oo_release_OCapBridgeRecord(OCapBridgeRecord v);
#ifndef OO_HAVE_OoL_OCapBridgeRecord
#define OO_HAVE_OoL_OCapBridgeRecord
typedef struct OoL_OCapBridgeRecord { struct OCapBridgeRecord *data; long long len; long long cap; } OoL_OCapBridgeRecord;
static inline void oo_retain_OoL_OCapBridgeRecord(OoL_OCapBridgeRecord v);
static inline void oo_release_OoL_OCapBridgeRecord(OoL_OCapBridgeRecord v);
#endif
#endif
#ifndef OO_FWD_OCapBridgeRecord
#define OO_FWD_OCapBridgeRecord
typedef struct OCapBridgeRecord OCapBridgeRecord;
static inline void oo_retain_OCapBridgeRecord(OCapBridgeRecord v);
static inline void oo_release_OCapBridgeRecord(OCapBridgeRecord v);
#ifndef OO_HAVE_OoL_OCapBridgeRecord
#define OO_HAVE_OoL_OCapBridgeRecord
typedef struct OoL_OCapBridgeRecord { struct OCapBridgeRecord *data; long long len; long long cap; } OoL_OCapBridgeRecord;
static inline void oo_retain_OoL_OCapBridgeRecord(OoL_OCapBridgeRecord v);
static inline void oo_release_OoL_OCapBridgeRecord(OoL_OCapBridgeRecord v);
#endif
#endif
#ifndef OO_TY_OCapBridgeRecord
#define OO_TY_OCapBridgeRecord
typedef struct OCapBridgeRecord { OoStr cap_name; OoStr language_token; long long rights_mask; } OCapBridgeRecord;
static inline void oo_retain_OCapBridgeRecord(OCapBridgeRecord v) { oo_str_retain(v.cap_name); oo_str_retain(v.language_token); }
static inline void oo_release_OCapBridgeRecord(OCapBridgeRecord v) { oo_str_release(v.cap_name); oo_str_release(v.language_token); }
#endif
#ifndef OO_TY_OoRes_OCapBridgeRecord
#define OO_TY_OoRes_OCapBridgeRecord
typedef struct OoRes_OCapBridgeRecord { int ok; OCapBridgeRecord val; OoStr err; } OoRes_OCapBridgeRecord;
#endif
#ifndef OO_FNS_OoRes_OCapBridgeRecord
#define OO_FNS_OoRes_OCapBridgeRecord
static inline OoRes_OCapBridgeRecord oo_res_OCapBridgeRecord_S_ok(OCapBridgeRecord v) { OoRes_OCapBridgeRecord r; r.ok = 1; r.val = v; memset(&r.err, 0, sizeof(OoStr)); return r; }
static inline OoRes_OCapBridgeRecord oo_res_OCapBridgeRecord_S_err(OoStr e) { OoRes_OCapBridgeRecord r; r.ok = 0; memset(&r.val, 0, sizeof(OCapBridgeRecord)); r.err = e; return r; }
static inline void oo_retain_OoRes_OCapBridgeRecord(OoRes_OCapBridgeRecord v) {
  if (v.ok) { oo_retain_OCapBridgeRecord(v.val); }
  if (!v.ok) { oo_retain_S(v.err); }
}
static inline void oo_release_OoRes_OCapBridgeRecord(OoRes_OCapBridgeRecord v) {
  if (v.ok) { oo_release_OCapBridgeRecord(v.val); }
  if (!v.ok) { oo_release_S(v.err); }
}
#endif
#ifndef OO_TY_OoOpt_OCapBridgeRecord
#define OO_TY_OoOpt_OCapBridgeRecord
typedef struct OoOpt_OCapBridgeRecord { int has_val; OCapBridgeRecord val; } OoOpt_OCapBridgeRecord;
#endif
#ifndef OO_FNS_OoOpt_OCapBridgeRecord
#define OO_FNS_OoOpt_OCapBridgeRecord
static inline OoOpt_OCapBridgeRecord oo_opt_OCapBridgeRecord_some(OCapBridgeRecord v) { OoOpt_OCapBridgeRecord o; o.has_val = 1; o.val = v; return o; }
static inline OoOpt_OCapBridgeRecord oo_opt_OCapBridgeRecord_none(void) { OoOpt_OCapBridgeRecord o; o.has_val = 0; memset(&o.val, 0, sizeof(OCapBridgeRecord)); return o; }
static inline void oo_retain_OoOpt_OCapBridgeRecord(OoOpt_OCapBridgeRecord v) {
  if (v.has_val) { oo_retain_OCapBridgeRecord(v.val); }
}
static inline void oo_release_OoOpt_OCapBridgeRecord(OoOpt_OCapBridgeRecord v) {
  if (v.has_val) { oo_release_OCapBridgeRecord(v.val); }
}
#endif
#ifndef OO_TY_OoRes_OoOpt_OCapBridgeRecord
#define OO_TY_OoRes_OoOpt_OCapBridgeRecord
typedef struct OoRes_OoOpt_OCapBridgeRecord { int ok; OoOpt_OCapBridgeRecord val; OoStr err; } OoRes_OoOpt_OCapBridgeRecord;
#endif
#ifndef OO_FNS_OoRes_OoOpt_OCapBridgeRecord
#define OO_FNS_OoRes_OoOpt_OCapBridgeRecord
static inline OoRes_OoOpt_OCapBridgeRecord oo_res_OoOpt_OCapBridgeRecord_S_ok(OoOpt_OCapBridgeRecord v) { OoRes_OoOpt_OCapBridgeRecord r; r.ok = 1; r.val = v; memset(&r.err, 0, sizeof(OoStr)); return r; }
static inline OoRes_OoOpt_OCapBridgeRecord oo_res_OoOpt_OCapBridgeRecord_S_err(OoStr e) { OoRes_OoOpt_OCapBridgeRecord r; r.ok = 0; memset(&r.val, 0, sizeof(OoOpt_OCapBridgeRecord)); r.err = e; return r; }
static inline void oo_retain_OoRes_OoOpt_OCapBridgeRecord(OoRes_OoOpt_OCapBridgeRecord v) {
  if (v.ok) { oo_retain_OoOpt_OCapBridgeRecord(v.val); }
  if (!v.ok) { oo_retain_S(v.err); }
}
static inline void oo_release_OoRes_OoOpt_OCapBridgeRecord(OoRes_OoOpt_OCapBridgeRecord v) {
  if (v.ok) { oo_release_OoOpt_OCapBridgeRecord(v.val); }
  if (!v.ok) { oo_release_S(v.err); }
}
#endif
#ifndef OO_TY_OoL_OCapBridgeRecord
#define OO_TY_OoL_OCapBridgeRecord
#ifndef OO_HAVE_OoL_OCapBridgeRecord
#define OO_HAVE_OoL_OCapBridgeRecord
typedef struct OoL_OCapBridgeRecord { OCapBridgeRecord *data; long long len; long long cap; } OoL_OCapBridgeRecord;
#endif
#ifndef OO_RETAIN_OoL_OCapBridgeRecord
#define OO_RETAIN_OoL_OCapBridgeRecord
static inline void oo_retain_OoL_OCapBridgeRecord(OoL_OCapBridgeRecord v) {
  if (v.data) { OoListHeader *hdr = ((OoListHeader*)v.data) - 1; __atomic_fetch_add(&hdr->ref_count, 1, __ATOMIC_ACQ_REL); }
}
static inline void oo_release_OoL_OCapBridgeRecord(OoL_OCapBridgeRecord v) {
  if (v.data) {
    OoListHeader *hdr = ((OoListHeader*)v.data) - 1;
    uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
    if (prev == 1) {
      for (long long i = 0; i < v.len; i++) { oo_release_OCapBridgeRecord(v.data[i]); }
      __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
      __atomic_thread_fence(__ATOMIC_RELEASE);
      oo_list_quota_release_bytes(v.cap, sizeof(OCapBridgeRecord));
      oo_payload_free(v.data);
    }
  }
}
#endif
#ifndef OO_FNS_OoL_OCapBridgeRecord
#define OO_FNS_OoL_OCapBridgeRecord
static inline OoL_OCapBridgeRecord oo_l_OCapBridgeRecord_new(void) { OoL_OCapBridgeRecord l; l.data = 0; l.len = 0; l.cap = 0; return l; }
static inline long long oo_l_OCapBridgeRecord_len(OoL_OCapBridgeRecord l) { return l.len; }
static inline OCapBridgeRecord oo_l_OCapBridgeRecord_get(OoL_OCapBridgeRecord l, long long i) {
  if (i < 0 || i >= l.len) { fprintf(stderr, "ERR\tolist_get OOB\n"); exit(1); }
  oo_retain_OCapBridgeRecord(l.data[i]);
  return l.data[i];
}
static inline OoL_OCapBridgeRecord oo_l_OCapBridgeRecord_set(OoL_OCapBridgeRecord l, long long i, OCapBridgeRecord v) {
  if (i < 0 || i >= l.len) { fprintf(stderr, "ERR\tolist_set OOB\n"); exit(1); }
  if (l.data) {
    OoListHeader *h = ((OoListHeader*)l.data) - 1;
    if (__atomic_load_n(&h->ref_count, __ATOMIC_ACQUIRE) == 1) {
      OCapBridgeRecord old = l.data[i];
      l.data[i] = v;
      oo_retain_OCapBridgeRecord(v);
      oo_release_OCapBridgeRecord(old);
      oo_retain_OoL_OCapBridgeRecord(l);
      return l;
    }
  }
  OoL_OCapBridgeRecord n;
  long long ncap = l.cap ? l.cap : l.len;
  n.data = (OCapBridgeRecord*)oo_list_alloc_payload(sizeof(OCapBridgeRecord), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OCapBridgeRecord));
    for (long long j = 0; j < l.len; j++) { if (j != i) oo_retain_OCapBridgeRecord(n.data[j]); }
  }
  n.data[i] = v;
  oo_retain_OCapBridgeRecord(v);
  n.len = l.len; n.cap = ncap;
  OoListHeader *hdr = ((OoListHeader*)n.data) - 1;
  __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  return n;
}
static inline OoL_OCapBridgeRecord oo_l_OCapBridgeRecord_push(OoL_OCapBridgeRecord l, OCapBridgeRecord v) {
  if (l.data && l.len < l.cap) {
    OoListHeader *h = ((OoListHeader*)l.data) - 1;
    if (__atomic_load_n(&h->ref_count, __ATOMIC_ACQUIRE) == 1) {
      oo_retain_OCapBridgeRecord(v);
      l.data[l.len] = v;
      l.len = l.len + 1;
      oo_retain_OoL_OCapBridgeRecord(l);
      return l;
    }
  }
  OoL_OCapBridgeRecord n;
  long long ncap = l.cap ? l.cap : 8;
  while (ncap < l.len + 1) ncap = ncap * 2;
  n.data = (OCapBridgeRecord*)oo_list_alloc_payload(sizeof(OCapBridgeRecord), (size_t)ncap);
  if (l.data && l.len > 0) {
    for (long long i = 0; i < l.len; i++) { n.data[i] = l.data[i]; oo_retain_OCapBridgeRecord(n.data[i]); }
  }
  oo_retain_OCapBridgeRecord(v);
  n.data[l.len] = v; n.len = l.len + 1; n.cap = ncap;
  OoListHeader *hdr = ((OoListHeader*)n.data) - 1;
  __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  return n;
}
#endif
#endif
#ifndef OO_TY_OoL_OoL_OCapBridgeRecord
#define OO_TY_OoL_OoL_OCapBridgeRecord
#ifndef OO_HAVE_OoL_OoL_OCapBridgeRecord
#define OO_HAVE_OoL_OoL_OCapBridgeRecord
typedef struct OoL_OoL_OCapBridgeRecord { OoL_OCapBridgeRecord *data; long long len; long long cap; } OoL_OoL_OCapBridgeRecord;
#endif
#ifndef OO_RETAIN_OoL_OoL_OCapBridgeRecord
#define OO_RETAIN_OoL_OoL_OCapBridgeRecord
static inline void oo_retain_OoL_OoL_OCapBridgeRecord(OoL_OoL_OCapBridgeRecord v) {
  if (v.data) { OoListHeader *hdr = ((OoListHeader*)v.data) - 1; __atomic_fetch_add(&hdr->ref_count, 1, __ATOMIC_ACQ_REL); }
}
static inline void oo_release_OoL_OoL_OCapBridgeRecord(OoL_OoL_OCapBridgeRecord v) {
  if (v.data) {
    OoListHeader *hdr = ((OoListHeader*)v.data) - 1;
    uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
    if (prev == 1) {
      for (long long i = 0; i < v.len; i++) { oo_release_OoL_OCapBridgeRecord(v.data[i]); }
      __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
      __atomic_thread_fence(__ATOMIC_RELEASE);
      oo_list_quota_release_bytes(v.cap, sizeof(OoL_OCapBridgeRecord));
      oo_payload_free(v.data);
    }
  }
}
#endif
#ifndef OO_FNS_OoL_OoL_OCapBridgeRecord
#define OO_FNS_OoL_OoL_OCapBridgeRecord
static inline OoL_OoL_OCapBridgeRecord oo_l_OoL_OCapBridgeRecord_new(void) { OoL_OoL_OCapBridgeRecord l; l.data = 0; l.len = 0; l.cap = 0; return l; }
static inline long long oo_l_OoL_OCapBridgeRecord_len(OoL_OoL_OCapBridgeRecord l) { return l.len; }
static inline OoL_OCapBridgeRecord oo_l_OoL_OCapBridgeRecord_get(OoL_OoL_OCapBridgeRecord l, long long i) {
  if (i < 0 || i >= l.len) { fprintf(stderr, "ERR\tolist_get OOB\n"); exit(1); }
  oo_retain_OoL_OCapBridgeRecord(l.data[i]);
  return l.data[i];
}
static inline OoL_OoL_OCapBridgeRecord oo_l_OoL_OCapBridgeRecord_set(OoL_OoL_OCapBridgeRecord l, long long i, OoL_OCapBridgeRecord v) {
  if (i < 0 || i >= l.len) { fprintf(stderr, "ERR\tolist_set OOB\n"); exit(1); }
  if (l.data) {
    OoListHeader *h = ((OoListHeader*)l.data) - 1;
    if (__atomic_load_n(&h->ref_count, __ATOMIC_ACQUIRE) == 1) {
      OoL_OCapBridgeRecord old = l.data[i];
      l.data[i] = v;
      oo_retain_OoL_OCapBridgeRecord(v);
      oo_release_OoL_OCapBridgeRecord(old);
      oo_retain_OoL_OoL_OCapBridgeRecord(l);
      return l;
    }
  }
  OoL_OoL_OCapBridgeRecord n;
  long long ncap = l.cap ? l.cap : l.len;
  n.data = (OoL_OCapBridgeRecord*)oo_list_alloc_payload(sizeof(OoL_OCapBridgeRecord), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoL_OCapBridgeRecord));
    for (long long j = 0; j < l.len; j++) { if (j != i) oo_retain_OoL_OCapBridgeRecord(n.data[j]); }
  }
  n.data[i] = v;
  oo_retain_OoL_OCapBridgeRecord(v);
  n.len = l.len; n.cap = ncap;
  OoListHeader *hdr = ((OoListHeader*)n.data) - 1;
  __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  return n;
}
static inline OoL_OoL_OCapBridgeRecord oo_l_OoL_OCapBridgeRecord_push(OoL_OoL_OCapBridgeRecord l, OoL_OCapBridgeRecord v) {
  if (l.data && l.len < l.cap) {
    OoListHeader *h = ((OoListHeader*)l.data) - 1;
    if (__atomic_load_n(&h->ref_count, __ATOMIC_ACQUIRE) == 1) {
      oo_retain_OoL_OCapBridgeRecord(v);
      l.data[l.len] = v;
      l.len = l.len + 1;
      oo_retain_OoL_OoL_OCapBridgeRecord(l);
      return l;
    }
  }
  OoL_OoL_OCapBridgeRecord n;
  long long ncap = l.cap ? l.cap : 8;
  while (ncap < l.len + 1) ncap = ncap * 2;
  n.data = (OoL_OCapBridgeRecord*)oo_list_alloc_payload(sizeof(OoL_OCapBridgeRecord), (size_t)ncap);
  if (l.data && l.len > 0) {
    for (long long i = 0; i < l.len; i++) { n.data[i] = l.data[i]; oo_retain_OoL_OCapBridgeRecord(n.data[i]); }
  }
  oo_retain_OoL_OCapBridgeRecord(v);
  n.data[l.len] = v; n.len = l.len + 1; n.cap = ncap;
  OoListHeader *hdr = ((OoListHeader*)n.data) - 1;
  __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  return n;
}
#endif
#endif
#ifndef OO_TY_OoL_OoL_OoL_OCapBridgeRecord
#define OO_TY_OoL_OoL_OoL_OCapBridgeRecord
#ifndef OO_HAVE_OoL_OoL_OoL_OCapBridgeRecord
#define OO_HAVE_OoL_OoL_OoL_OCapBridgeRecord
typedef struct OoL_OoL_OoL_OCapBridgeRecord { OoL_OoL_OCapBridgeRecord *data; long long len; long long cap; } OoL_OoL_OoL_OCapBridgeRecord;
#endif
#ifndef OO_RETAIN_OoL_OoL_OoL_OCapBridgeRecord
#define OO_RETAIN_OoL_OoL_OoL_OCapBridgeRecord
static inline void oo_retain_OoL_OoL_OoL_OCapBridgeRecord(OoL_OoL_OoL_OCapBridgeRecord v) {
  if (v.data) { OoListHeader *hdr = ((OoListHeader*)v.data) - 1; __atomic_fetch_add(&hdr->ref_count, 1, __ATOMIC_ACQ_REL); }
}
static inline void oo_release_OoL_OoL_OoL_OCapBridgeRecord(OoL_OoL_OoL_OCapBridgeRecord v) {
  if (v.data) {
    OoListHeader *hdr = ((OoListHeader*)v.data) - 1;
    uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
    if (prev == 1) {
      for (long long i = 0; i < v.len; i++) { oo_release_OoL_OoL_OCapBridgeRecord(v.data[i]); }
      __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
      __atomic_thread_fence(__ATOMIC_RELEASE);
      oo_list_quota_release_bytes(v.cap, sizeof(OoL_OoL_OCapBridgeRecord));
      oo_payload_free(v.data);
    }
  }
}
#endif
#ifndef OO_FNS_OoL_OoL_OoL_OCapBridgeRecord
#define OO_FNS_OoL_OoL_OoL_OCapBridgeRecord
static inline OoL_OoL_OoL_OCapBridgeRecord oo_l_OoL_OoL_OCapBridgeRecord_new(void) { OoL_OoL_OoL_OCapBridgeRecord l; l.data = 0; l.len = 0; l.cap = 0; return l; }
static inline long long oo_l_OoL_OoL_OCapBridgeRecord_len(OoL_OoL_OoL_OCapBridgeRecord l) { return l.len; }
static inline OoL_OoL_OCapBridgeRecord oo_l_OoL_OoL_OCapBridgeRecord_get(OoL_OoL_OoL_OCapBridgeRecord l, long long i) {
  if (i < 0 || i >= l.len) { fprintf(stderr, "ERR\tolist_get OOB\n"); exit(1); }
  oo_retain_OoL_OoL_OCapBridgeRecord(l.data[i]);
  return l.data[i];
}
static inline OoL_OoL_OoL_OCapBridgeRecord oo_l_OoL_OoL_OCapBridgeRecord_set(OoL_OoL_OoL_OCapBridgeRecord l, long long i, OoL_OoL_OCapBridgeRecord v) {
  if (i < 0 || i >= l.len) { fprintf(stderr, "ERR\tolist_set OOB\n"); exit(1); }
  if (l.data) {
    OoListHeader *h = ((OoListHeader*)l.data) - 1;
    if (__atomic_load_n(&h->ref_count, __ATOMIC_ACQUIRE) == 1) {
      OoL_OoL_OCapBridgeRecord old = l.data[i];
      l.data[i] = v;
      oo_retain_OoL_OoL_OCapBridgeRecord(v);
      oo_release_OoL_OoL_OCapBridgeRecord(old);
      oo_retain_OoL_OoL_OoL_OCapBridgeRecord(l);
      return l;
    }
  }
  OoL_OoL_OoL_OCapBridgeRecord n;
  long long ncap = l.cap ? l.cap : l.len;
  n.data = (OoL_OoL_OCapBridgeRecord*)oo_list_alloc_payload(sizeof(OoL_OoL_OCapBridgeRecord), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoL_OoL_OCapBridgeRecord));
    for (long long j = 0; j < l.len; j++) { if (j != i) oo_retain_OoL_OoL_OCapBridgeRecord(n.data[j]); }
  }
  n.data[i] = v;
  oo_retain_OoL_OoL_OCapBridgeRecord(v);
  n.len = l.len; n.cap = ncap;
  OoListHeader *hdr = ((OoListHeader*)n.data) - 1;
  __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  return n;
}
static inline OoL_OoL_OoL_OCapBridgeRecord oo_l_OoL_OoL_OCapBridgeRecord_push(OoL_OoL_OoL_OCapBridgeRecord l, OoL_OoL_OCapBridgeRecord v) {
  if (l.data && l.len < l.cap) {
    OoListHeader *h = ((OoListHeader*)l.data) - 1;
    if (__atomic_load_n(&h->ref_count, __ATOMIC_ACQUIRE) == 1) {
      oo_retain_OoL_OoL_OCapBridgeRecord(v);
      l.data[l.len] = v;
      l.len = l.len + 1;
      oo_retain_OoL_OoL_OoL_OCapBridgeRecord(l);
      return l;
    }
  }
  OoL_OoL_OoL_OCapBridgeRecord n;
  long long ncap = l.cap ? l.cap : 8;
  while (ncap < l.len + 1) ncap = ncap * 2;
  n.data = (OoL_OoL_OCapBridgeRecord*)oo_list_alloc_payload(sizeof(OoL_OoL_OCapBridgeRecord), (size_t)ncap);
  if (l.data && l.len > 0) {
    for (long long i = 0; i < l.len; i++) { n.data[i] = l.data[i]; oo_retain_OoL_OoL_OCapBridgeRecord(n.data[i]); }
  }
  oo_retain_OoL_OoL_OCapBridgeRecord(v);
  n.data[l.len] = v; n.len = l.len + 1; n.cap = ncap;
  OoListHeader *hdr = ((OoListHeader*)n.data) - 1;
  __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  return n;
}
#endif
#endif
#ifndef OO_TY_OoRes_OoL_OCapBridgeRecord
#define OO_TY_OoRes_OoL_OCapBridgeRecord
typedef struct OoRes_OoL_OCapBridgeRecord { int ok; OoL_OCapBridgeRecord val; OoStr err; } OoRes_OoL_OCapBridgeRecord;
#endif
#ifndef OO_FNS_OoRes_OoL_OCapBridgeRecord
#define OO_FNS_OoRes_OoL_OCapBridgeRecord
static inline OoRes_OoL_OCapBridgeRecord oo_res_OoL_OCapBridgeRecord_S_ok(OoL_OCapBridgeRecord v) { OoRes_OoL_OCapBridgeRecord r; r.ok = 1; r.val = v; memset(&r.err, 0, sizeof(OoStr)); return r; }
static inline OoRes_OoL_OCapBridgeRecord oo_res_OoL_OCapBridgeRecord_S_err(OoStr e) { OoRes_OoL_OCapBridgeRecord r; r.ok = 0; memset(&r.val, 0, sizeof(OoL_OCapBridgeRecord)); r.err = e; return r; }
static inline void oo_retain_OoRes_OoL_OCapBridgeRecord(OoRes_OoL_OCapBridgeRecord v) {
  if (v.ok) { oo_retain_OoL_OCapBridgeRecord(v.val); }
  if (!v.ok) { oo_retain_S(v.err); }
}
static inline void oo_release_OoRes_OoL_OCapBridgeRecord(OoRes_OoL_OCapBridgeRecord v) {
  if (v.ok) { oo_release_OoL_OCapBridgeRecord(v.val); }
  if (!v.ok) { oo_release_S(v.err); }
}
#endif
#ifndef OO_TY_OoOpt_OoL_OCapBridgeRecord
#define OO_TY_OoOpt_OoL_OCapBridgeRecord
typedef struct OoOpt_OoL_OCapBridgeRecord { int has_val; OoL_OCapBridgeRecord val; } OoOpt_OoL_OCapBridgeRecord;
#endif
#ifndef OO_FNS_OoOpt_OoL_OCapBridgeRecord
#define OO_FNS_OoOpt_OoL_OCapBridgeRecord
static inline OoOpt_OoL_OCapBridgeRecord oo_opt_OoL_OCapBridgeRecord_some(OoL_OCapBridgeRecord v) { OoOpt_OoL_OCapBridgeRecord o; o.has_val = 1; o.val = v; return o; }
static inline OoOpt_OoL_OCapBridgeRecord oo_opt_OoL_OCapBridgeRecord_none(void) { OoOpt_OoL_OCapBridgeRecord o; o.has_val = 0; memset(&o.val, 0, sizeof(OoL_OCapBridgeRecord)); return o; }
static inline void oo_retain_OoOpt_OoL_OCapBridgeRecord(OoOpt_OoL_OCapBridgeRecord v) {
  if (v.has_val) { oo_retain_OoL_OCapBridgeRecord(v.val); }
}
static inline void oo_release_OoOpt_OoL_OCapBridgeRecord(OoOpt_OoL_OCapBridgeRecord v) {
  if (v.has_val) { oo_release_OoL_OCapBridgeRecord(v.val); }
}
#endif
#ifndef OO_TY_OoRes_OoOpt_OoL_OCapBridgeRecord
#define OO_TY_OoRes_OoOpt_OoL_OCapBridgeRecord
typedef struct OoRes_OoOpt_OoL_OCapBridgeRecord { int ok; OoOpt_OoL_OCapBridgeRecord val; OoStr err; } OoRes_OoOpt_OoL_OCapBridgeRecord;
#endif
#ifndef OO_FNS_OoRes_OoOpt_OoL_OCapBridgeRecord
#define OO_FNS_OoRes_OoOpt_OoL_OCapBridgeRecord
static inline OoRes_OoOpt_OoL_OCapBridgeRecord oo_res_OoOpt_OoL_OCapBridgeRecord_S_ok(OoOpt_OoL_OCapBridgeRecord v) { OoRes_OoOpt_OoL_OCapBridgeRecord r; r.ok = 1; r.val = v; memset(&r.err, 0, sizeof(OoStr)); return r; }
static inline OoRes_OoOpt_OoL_OCapBridgeRecord oo_res_OoOpt_OoL_OCapBridgeRecord_S_err(OoStr e) { OoRes_OoOpt_OoL_OCapBridgeRecord r; r.ok = 0; memset(&r.val, 0, sizeof(OoOpt_OoL_OCapBridgeRecord)); r.err = e; return r; }
static inline void oo_retain_OoRes_OoOpt_OoL_OCapBridgeRecord(OoRes_OoOpt_OoL_OCapBridgeRecord v) {
  if (v.ok) { oo_retain_OoOpt_OoL_OCapBridgeRecord(v.val); }
  if (!v.ok) { oo_retain_S(v.err); }
}
static inline void oo_release_OoRes_OoOpt_OoL_OCapBridgeRecord(OoRes_OoOpt_OoL_OCapBridgeRecord v) {
  if (v.ok) { oo_release_OoOpt_OoL_OCapBridgeRecord(v.val); }
  if (!v.ok) { oo_release_S(v.err); }
}
#endif
#ifndef OO_TY_OoL_OCapBridgeRecord
#define OO_TY_OoL_OCapBridgeRecord
#ifndef OO_HAVE_OoL_OCapBridgeRecord
#define OO_HAVE_OoL_OCapBridgeRecord
typedef struct OoL_OCapBridgeRecord { OCapBridgeRecord *data; long long len; long long cap; } OoL_OCapBridgeRecord;
#endif
#endif
#ifndef OO_FNS_OoL_OCapBridgeRecord
#define OO_FNS_OoL_OCapBridgeRecord
#define OO_TY_OoL_OCapBridgeRecord
static inline OoL_OCapBridgeRecord oo_l_OCapBridgeRecord_new(void) { OoL_OCapBridgeRecord l; l.data=0; l.len=0; l.cap=0; return l; }
static inline long long oo_l_OCapBridgeRecord_len(OoL_OCapBridgeRecord l) { return l.len; }
static inline OCapBridgeRecord oo_l_OCapBridgeRecord_get(OoL_OCapBridgeRecord l, long long i) {
  if (i<0||i>=l.len) { fprintf(stderr,"ERR\tolist_get OOB\n"); exit(1); }
  oo_retain_OCapBridgeRecord(l.data[i]); return l.data[i]; }
static inline OoL_OCapBridgeRecord oo_l_OCapBridgeRecord_set(OoL_OCapBridgeRecord l, long long i, OCapBridgeRecord v) {
  if (i<0||i>=l.len) { fprintf(stderr,"ERR\tolist_set OOB\n"); exit(1); }
  l.data[i] = v; return l; }
static inline OoL_OCapBridgeRecord oo_l_OCapBridgeRecord_push(OoL_OCapBridgeRecord l, OCapBridgeRecord v) {
  OoL_OCapBridgeRecord n; long long ncap = l.cap ? l.cap : 8;
  while (ncap < l.len + 1) ncap = ncap * 2;
  n.data = (OCapBridgeRecord*)oo_list_alloc_payload(sizeof(OCapBridgeRecord), (size_t)ncap);
  if (l.data && l.len > 0) { for (long long i = 0; i < l.len; i++) { n.data[i] = l.data[i]; oo_retain_OCapBridgeRecord(n.data[i]); } }
  oo_retain_OCapBridgeRecord(v);
  n.data[l.len] = v; n.len = l.len + 1; n.cap = ncap;
  OoListHeader *hdr = ((OoListHeader*)n.data) - 1;
  __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); return n; }
#ifndef OO_RETAIN_OoL_OCapBridgeRecord
#define OO_RETAIN_OoL_OCapBridgeRecord
static inline void oo_retain_OoL_OCapBridgeRecord(OoL_OCapBridgeRecord v) { if (v.data) { OoListHeader *hdr = ((OoListHeader*)v.data)-1; __atomic_fetch_add(&hdr->ref_count, 1, __ATOMIC_ACQ_REL); } }
static inline void oo_release_OoL_OCapBridgeRecord(OoL_OCapBridgeRecord v) { if (v.data) { OoListHeader *hdr = ((OoListHeader*)v.data)-1; if (__atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL) == 1) { for (long long i = 0; i < v.len; i++) { oo_release_OCapBridgeRecord(v.data[i]); } oo_payload_free(v.data); } } }
#endif
#endif
static OCapBridgeRecord _oo_ocap_to_oodar_record_new(OoStr name, OoStr token, long long mask);
__attribute__((visibility("hidden"))) OCapBridgeRecord ocap_to_oodar_record_for(OoStr name);
__attribute__((visibility("hidden"))) long long ocap_to_oodar_rights_for_name(OoStr name);
__attribute__((visibility("hidden"))) OoSList ocap_to_oodar_all_names(void);
__attribute__((visibility("hidden"))) int ocap_to_oodar_has_permission(OoStr name, long long required);
#line 1 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo"
#line 1 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo"

#line 56 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo"
#ifndef OO_FN__oo_ocap_to_oodar_record_new
#define OO_FN__oo_ocap_to_oodar_record_new
static OCapBridgeRecord _oo_ocap_to_oodar_record_new(OoStr name, OoStr token, long long mask) {
#undef OO_ENS_CHECK
#define OO_ENS_CHECK(result) (1)
#line 57 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  OCapBridgeRecord __ret_val = ((OCapBridgeRecord){ .cap_name = name, .language_token = token, .rights_mask = mask });
  oo_retain_OCapBridgeRecord(__ret_val); 
  return __ret_val;
}
#endif

#line 60 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo"
#ifndef OO_FN_ocap_to_oodar_record_for
#define OO_FN_ocap_to_oodar_record_for
__attribute__((visibility("hidden"))) OCapBridgeRecord ocap_to_oodar_record_for(OoStr name) {
#undef OO_ENS_CHECK
#define OO_ENS_CHECK(result) (1)
#line 61 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("FsReadCap"))) {
#line 61 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 30 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("FsReadCap"), oo_str_lit("fsread"), 1LL);
  return __ret_val;
}
#line 62 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("FsWriteCap"))) {
#line 62 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 31 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("FsWriteCap"), oo_str_lit("fswrite"), 3LL);
  return __ret_val;
}
#line 63 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("NetCap"))) {
#line 63 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 27 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("NetCap"), oo_str_lit("net"), 3LL);
  return __ret_val;
}
#line 64 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("TcpCap"))) {
#line 64 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 27 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("TcpCap"), oo_str_lit("tcp"), 3LL);
  return __ret_val;
}
#line 65 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("UdpCap"))) {
#line 65 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 27 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("UdpCap"), oo_str_lit("udp"), 3LL);
  return __ret_val;
}
#line 66 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("SysCap"))) {
#line 66 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 27 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("SysCap"), oo_str_lit("sys"), 7LL);
  return __ret_val;
}
#line 67 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("ProcessCap"))) {
#line 67 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 31 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("ProcessCap"), oo_str_lit("process"), 7LL);
  return __ret_val;
}
#line 68 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("EnvCap"))) {
#line 68 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 27 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("EnvCap"), oo_str_lit("env"), 1LL);
  return __ret_val;
}
#line 69 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("TimeCap"))) {
#line 69 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 28 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("TimeCap"), oo_str_lit("time"), 1LL);
  return __ret_val;
}
#line 70 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("RandCap"))) {
#line 70 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 28 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("RandCap"), oo_str_lit("rand"), 1LL);
  return __ret_val;
}
#line 71 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("AllocCap"))) {
#line 71 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 29 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("AllocCap"), oo_str_lit("alloc"), 3LL);
  return __ret_val;
}
#line 72 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("ThreadCap"))) {
#line 72 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 30 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("ThreadCap"), oo_str_lit("thread"), 7LL);
  return __ret_val;
}
#line 73 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("GpuCap"))) {
#line 73 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 27 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("GpuCap"), oo_str_lit("gpu"), 7LL);
  return __ret_val;
}
#line 74 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("FfiCap"))) {
#line 74 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 27 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("FfiCap"), oo_str_lit("ffi"), 7LL);
  return __ret_val;
}
#line 75 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("FsCap"))) {
#line 75 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 26 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("FsCap"), oo_str_lit("fs"), 31LL);
  return __ret_val;
}
#line 76 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("ArenaCap"))) {
#line 76 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 29 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("ArenaCap"), oo_str_lit("arena"), 11LL);
  return __ret_val;
}
#line 77 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("MetricsCap"))) {
#line 77 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 31 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("MetricsCap"), oo_str_lit("metrics"), 1LL);
  return __ret_val;
}
#line 78 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("SignCap"))) {
#line 78 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 28 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("SignCap"), oo_str_lit("sign"), 3LL);
  return __ret_val;
}
#line 79 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("BindCap"))) {
#line 79 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 28 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("BindCap"), oo_str_lit("bind"), 3LL);
  return __ret_val;
}
#line 80 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
if (oo_str_eq(name, oo_str_lit("CompilerReadCap"))) {
#line 80 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 36 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit("CompilerReadCap"), oo_str_lit("compiler_read"), 1LL);
  return __ret_val;
}
#line 81 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  OCapBridgeRecord __ret_val = _oo_ocap_to_oodar_record_new(oo_str_lit(""), oo_str_lit(""), 0LL);
  return __ret_val;
}
#endif

#line 84 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo"
#ifndef OO_FN_ocap_to_oodar_rights_for_name
#define OO_FN_ocap_to_oodar_rights_for_name
__attribute__((visibility("hidden"))) long long ocap_to_oodar_rights_for_name(OoStr name) {
#undef OO_ENS_CHECK
#define OO_ENS_CHECK(result) (1)
#line 85 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  long long __ret_val = ocap_to_oodar_record_for(name).rights_mask;
  return __ret_val;
}
#endif

#line 88 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo"
#ifndef OO_FN_ocap_to_oodar_all_names
#define OO_FN_ocap_to_oodar_all_names
__attribute__((visibility("hidden"))) OoSList ocap_to_oodar_all_names(void) {
#undef OO_ENS_CHECK
#define OO_ENS_CHECK(result) (1)
#line 89 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  OoSList names_lvl2 = oo_slist_new();
#line 90 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 90 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("FsReadCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 91 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 91 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("FsWriteCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 92 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 92 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("NetCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 93 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 93 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("TcpCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 94 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 94 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("UdpCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 95 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 95 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("SysCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 96 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 96 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("ProcessCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 97 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 97 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("EnvCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 98 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 98 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("TimeCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 99 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 99 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("RandCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 100 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 100 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("AllocCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 101 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 101 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("ThreadCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 102 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 102 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("GpuCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 103 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 103 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("FfiCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 104 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 104 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("FsCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 105 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 105 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("ArenaCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 106 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 106 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("MetricsCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 107 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 107 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("SignCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 108 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 108 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("BindCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 109 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
#line 109 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  { OoStr __pa = oo_str_lit("CompilerReadCap"); OoSList __tmp = names_lvl2; names_lvl2 = oo_slist_push(names_lvl2, __pa); oo_str_release(__pa); oo_slist_release(__tmp); }
#line 110 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  OoSList __ret_val = names_lvl2;
  oo_slist_retain(__ret_val); 
  oo_slist_release(names_lvl2); 
  return __ret_val;
  oo_slist_release(names_lvl2); 
}
#endif

#line 113 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo"
#ifndef OO_FN_ocap_to_oodar_has_permission
#define OO_FN_ocap_to_oodar_has_permission
__attribute__((visibility("hidden"))) int ocap_to_oodar_has_permission(OoStr name, long long required) {
#undef OO_ENS_CHECK
#define OO_ENS_CHECK(result) (1)
#line 114 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  long long granted_lvl2 = ocap_to_oodar_rights_for_name(name);
#line 115 "/home/jeryd/Projects/openOODA/oodar/../std/sec/capability/ocap_to_oodar.oo" /* col 5 */
  int __ret_val = (((granted_lvl2 & required)) == required);
  return __ret_val;
}
#endif
