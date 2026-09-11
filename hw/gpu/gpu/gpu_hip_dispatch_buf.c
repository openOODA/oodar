/* gpu/gpu_hip_dispatch_buf.c — OoFloatBuf-typed GPU dispatchers.
 *
 * Phase 3 sample split: the raw-pointer API (gpu_hip_dispatch.c) and
 * the bounds-checked API (this file) live in different TUs so the
 * umbrella stays under the 256-line cap per file.
 *
 * The bounds metadata travels with the OoFloatBuf handle; the
 * dispatcher refuses OOB before reaching the kernel. Same fail-closed
 * posture as the cap gate. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The launcher table typedef is in gpu.c. */
OoHipKernels *oo_hip_kernels(void);
int oo_hip_so_bind(void);
int oo_gpu_init(long long cap);

/* Phase 3 sample: opaque bounds-checked buffer constructor. */
OoFloatBuf oo_float_buf_new(long long cap, long long len) {
  OoFloatBuf b;
  b.data = NULL;
  b.len = 0;
  b.cap = 0;
  if (cap <= 0 || len <= 0 || len > cap) return b;
  /* Caller must have a process cap or alloc cap; we don't gate here
   * to keep the constructor inlinable. The GPU dispatcher below
   * gates on the caller's cap. */
  b.data = (float *)malloc((size_t)(cap * sizeof(float)));
  if (!b.data) return b;
  b.cap = cap;
  b.len = len;
  return b;
}

OoResS oo_gpu_hip_vec_add_buf(long long cap, OoFloatBuf a, OoFloatBuf b, OoFloatBuf c) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_hip_vec_add_buf");
  oo_gpu_init(cap);
  /* Bounds check: every buf must have data + len > 0 + len ≤ cap.
   * Critical: all three bufs must have the same len (vec_add is
   * element-wise; mismatched lengths are a logic bug, not a UB
   * issue, but we still refuse). */
  if (!a.data || !b.data || !c.data) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tvec_add_buf null buf"); return r;
  }
  if (a.len <= 0 || b.len <= 0 || c.len <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tvec_add_buf zero len"); return r;
  }
  if (a.len != b.len || a.len != c.len) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tvec_add_buf length mismatch"); return r;
  }
  if (a.len > a.cap || b.len > b.cap || c.len > c.cap) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tvec_add_buf cap overflow"); return r;
  }
  if (!oo_hip_so_bind() || !oo_hip_kernels()->vec_add_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tliboo_hip.so absent"); return r;
  }
  int n = (int)a.len;
  int rc = oo_hip_kernels()->vec_add_launch(a.data, b.data, c.data, n);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("hip gfx1100 vec_add_buf MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\thip\tvec_add_buf numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\thip\tvec_add_buf launch failed");
  return r;
}
