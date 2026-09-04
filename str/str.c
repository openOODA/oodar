#include "../oodar.h"
#include <stdarg.h>

char *oo_str_alloc_payload(size_t len) {
  char *data = (char *)oo_payload_alloc(sizeof(OoStrHeader), len + 1);
  OoStrHeader *hdr = ((OoStrHeader *)data) - 1;
  hdr->ref_count = 1;
  hdr->flags = 0;
  data[len] = 0;
  return data;
}

static int oo_str_hdr_ok(OoStr s) {
  if (!s.data) return 0;
  if (s.len < 0 || s.len > (1LL << 28)) return 0;
  if (((uintptr_t)s.data) < sizeof(OoStrHeader) + 8) return 0;
  OoStrHeader *hdr = ((OoStrHeader *)s.data) - 1;
  uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);
  if (rc == 0 || rc == UINT32_MAX) return 0;
  if (rc > 1000000u) return 0;
  uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);
  if (fl & OO_FLAG_STATIC) return 0;
  if (fl == 0xFFFFFFFFu) return 0;
  return 1;
}

void oo_str_retain(OoStr s) {
  if (!oo_str_hdr_ok(s)) return;
  OoStrHeader *hdr = ((OoStrHeader *)s.data) - 1;
  uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);
  uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);
  if (rc == 0 || rc == UINT32_MAX || (fl & OO_FLAG_STATIC) || fl == 0xFFFFFFFFu) return;
  if (rc > 1000000u) return;
  while (rc > 0 && rc < UINT32_MAX) {
    if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return;
    rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);
    fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);
    if (rc == 0 || rc == UINT32_MAX || (fl & OO_FLAG_STATIC) || fl == 0xFFFFFFFFu) return;
    if (rc > 1000000u) return;
  }
}

void oo_str_release(OoStr s) {
  if (!oo_str_hdr_ok(s)) return;
  OoStrHeader *hdr = ((OoStrHeader *)s.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    oo_payload_free(s.data);
  }
}

OoStr oo_str_lit(const char *s) {
  if (!s) return oo_str_intern_bytes("", 0);
  return oo_str_intern_bytes(s, (long long)strlen(s));
}

OoStr oo_chr(long long cp) {
  char *data = oo_str_alloc_payload(1);
  data[0] = (cp < 0) ? 0 : (cp > 255 ? 0 : (char)cp);
  OoStr r; r.data = data; r.len = 1; return r;
}

OoStr oo_str_xor_lit(const unsigned char *p, long long n, long long key) {
  OoStr r; long long i;
  if (!p || n <= 0 || n > (1LL << 28)) return oo_str_intern_bytes("", 0);
  r.len = n; r.data = oo_str_alloc_payload((size_t)n);
  for (i = 0; i < n; i++) r.data[i] = (char)(p[i] ^ (unsigned char)((key + i * 17) & 255));
  return r;
}

OoStr oo_str_concat(OoStr a, OoStr b) {
  long long al = (a.data && a.len > 0 && a.len < (1LL << 28)) ? a.len : 0;
  long long bl = (b.data && b.len > 0 && b.len < (1LL << 28)) ? b.len : 0;
  OoStr r; r.len = al + bl; r.data = oo_str_alloc_payload((size_t)r.len);
  if (al > 0) memcpy(r.data, a.data, (size_t)al);
  if (bl > 0) memcpy(r.data + al, b.data, (size_t)bl);
  return r;
}

OoStr oo_str_concat_list(OoSList lst) {
  long long total = 0;
  for (long long i = 0; i < lst.len; i++) {
    OoStr s = lst.data[i];
    long long l = (s.data && s.len > 0 && s.len < (1LL << 28)) ? s.len : 0;
    total += l;
  }
  OoStr r; r.len = total; r.data = oo_str_alloc_payload((size_t)total);
  long long off = 0;
  for (long long i = 0; i < lst.len; i++) {
    OoStr s = lst.data[i];
    long long l = (s.data && s.len > 0 && s.len < (1LL << 28)) ? s.len : 0;
    if (l > 0) { memcpy(r.data + off, s.data, (size_t)l); off += l; }
  }
  return r;
}

OoStr oo_str_concat_multi(int n, ...) {
  if (n <= 0) { OoStr r; r.len = 0; r.data = oo_str_alloc_payload(0); return r; }
  va_list ap; va_start(ap, n);
  va_list ap2; va_copy(ap2, ap);
  long long total = 0;
  for (int i = 0; i < n; i++) {
    OoStr s = va_arg(ap2, OoStr);
    long long l = (s.data && s.len > 0 && s.len < (1LL << 28)) ? s.len : 0;
    total += l;
  }
  va_end(ap2);
  OoStr r; r.len = total; r.data = oo_str_alloc_payload((size_t)total);
  long long off = 0;
  for (int i = 0; i < n; i++) {
    OoStr s = va_arg(ap, OoStr);
    long long l = (s.data && s.len > 0 && s.len < (1LL << 28)) ? s.len : 0;
    if (l > 0) { memcpy(r.data + off, s.data, (size_t)l); off += l; }
  }
  va_end(ap);
  return r;
}

long long oo_str_byte_len(OoStr s) { return s.len; }

/* OoResO_* retain/release pairs: result-with-optional types that hold
 * either a payload (val, has_val==1) or an error string (err, ok==0).
 * If ok==1 and has_val==1 → retain/release the payload. If ok==0 → retain/release the err. */
void oo_reso_i_retain(OoResO_I v) { if (!v.ok) oo_str_retain(v.err); }
void oo_reso_i_release(OoResO_I v) { if (!v.ok) oo_str_release(v.err); }
void oo_reso_s_retain(OoResO_S v) { if (v.ok && v.has_val) oo_str_retain(v.val); else if (!v.ok) oo_str_retain(v.err); }
void oo_reso_s_release(OoResO_S v) { if (v.ok && v.has_val) oo_str_release(v.val); else if (!v.ok) oo_str_release(v.err); }
void oo_reso_b_retain(OoResO_B v) { if (!v.ok) oo_str_retain(v.err); }
void oo_reso_b_release(OoResO_B v) { if (!v.ok) oo_str_release(v.err); }
void oo_reso_f_retain(OoResO_F v) { if (!v.ok) oo_str_retain(v.err); }
void oo_reso_f_release(OoResO_F v) { if (!v.ok) oo_str_release(v.err); }
void oo_reso_li_retain(OoResO_LI v) { if (v.ok && v.has_val) oo_ilist_retain(v.val); else if (!v.ok) oo_str_retain(v.err); }
void oo_reso_li_release(OoResO_LI v) { if (v.ok && v.has_val) oo_ilist_release(v.val); else if (!v.ok) oo_str_release(v.err); }
void oo_reso_ls_retain(OoResO_LS v) { if (v.ok && v.has_val) oo_slist_retain(v.val); else if (!v.ok) oo_str_retain(v.err); }
void oo_reso_ls_release(OoResO_LS v) { if (v.ok && v.has_val) oo_slist_release(v.val); else if (!v.ok) oo_str_release(v.err); }
void oo_reso_lf_retain(OoResO_LF v) { if (v.ok && v.has_val) oo_flist_retain(v.val); else if (!v.ok) oo_str_retain(v.err); }
void oo_reso_lf_release(OoResO_LF v) { if (v.ok && v.has_val) oo_flist_release(v.val); else if (!v.ok) oo_str_release(v.err); }
