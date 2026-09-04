#define _GNU_SOURCE 1
/* CHS runtime umbrella — single TU for existing gcc command lines */
#include "chs_rt_align.c"
#include "chs_rt_sandbox.c"
#include "chs_rt_cap.c"
#include "chs_rt_str.c"
#include "chs_rt_str_intern.c"
#include "chs_rt_str_int.c"
#include "chs_rt_str_tok.c"
#include "chs_rt_str_ops.c"
#include "chs_rt_emit_tmp.c"
#include "chs_rt_list.c"
#include "chs_rt_flist.c"
#include "chs_rt_llist.c"
#include "chs_rt_llist_s.c"
#include "chs_rt_llist_f.c"
#include "chs_rt_caps.c"
#include "chs_rt_sys.c"
#include "chs_rt_fetch.c"
#include "chs_rt_ffi_sec.c"
#include "chs_rt_ffi.c"
#include "chs_rt_hash.c"
#include "chs_rt_netfloor.c"
#include "chs_rt_tls.c"
#include "chs_rt_gpu.c"
#include "chs_rt_gpu_hip.c"
#include "chs_rt_thread.c"
#include "chs_rt_channel.c"
#include "chs_rt_actor.c"
#include "chs_rt_hitl.c"
#include "chs_rt_time_rand.c"
#include "chs_rt_alloc.c"
#include "chs_rt_arena.c"
#include "chs_rt_fs.c"
#include "chs_rt_print.c"
#include "chs_rt_math.c"
#include "chs_rt_crypto.c"
#include "chs_rt_meta.c"
#include "chs_rt_host.c"
#include "chs_rt_rlimit.c"
#include "chs_rt_landlock.c"
#include "chs_rt_dns.c"
#include "chs_rt_vision.c"
#include "chs_rt_xlang.c"
#include "chs_rt_sha3.c"
#include "chs_rt_aead.c"
#include "chs_rt_mlkem.c"
#include "chs_rt_mldsa.c"
#include "chs_rt_pq_sig.c"
#include "chs_rt_metrics.c"
#include "chs_rt_closure.c"
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

OoSList str_split(OoStr s, OoStr delim) {
  OoSList l = oo_slist_new();
  if (!s.data || s.len <= 0) return l;
  if (!delim.data || delim.len <= 0) {
    OoSList next = oo_slist_push(l, s);
    oo_slist_release(l);
    return next;
  }
  long long start = 0;
  for (long long i = 0; i + delim.len <= s.len; i++) {
    if (memcmp(s.data + i, delim.data, (size_t)delim.len) == 0) {
      OoStr part;
      part.len = i - start;
      part.data = oo_str_alloc_payload((size_t)part.len);
      if (part.len > 0) memcpy(part.data, s.data + start, (size_t)part.len);
      OoSList next = oo_slist_push(l, part);
      oo_slist_release(l);
      l = next;
      oo_str_release(part);
      i += delim.len - 1;
      start = i + 1;
    }
  }
  OoStr part;
  part.len = s.len - start;
  part.data = oo_str_alloc_payload((size_t)part.len);
  if (part.len > 0) memcpy(part.data, s.data + start, (size_t)part.len);
  OoSList next = oo_slist_push(l, part);
  oo_slist_release(l);
  l = next;
  oo_str_release(part);
  return l;
}

OoStr str_trim(OoStr s) {
  if (!s.data || s.len <= 0) {
    OoStr r;
    r.len = 0;
    r.data = oo_str_alloc_payload(0);
    return r;
  }
  long long start = 0;
  while (start < s.len && isspace((unsigned char)s.data[start])) {
    start++;
  }
  long long end = s.len;
  while (end > start && isspace((unsigned char)s.data[end - 1])) {
    end--;
  }
  OoStr r;
  r.len = end - start;
  r.data = oo_str_alloc_payload((size_t)r.len);
  if (r.len > 0) memcpy(r.data, s.data + start, (size_t)r.len);
  return r;
}

// Result[String, String] structural equality. Compares the ok bit and, if
// both sides are Ok, the payload strings via oo_str_eq.
int oo_res_eq_s(OoResS a, OoResS b) {
  if (a.ok != b.ok) return 0;
  if (a.ok == 0) return 1;
  return oo_str_eq(a.val, b.val);
}
