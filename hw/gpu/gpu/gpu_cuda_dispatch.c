/* gpu/gpu_cuda_dispatch.c — the five CUDA kernel dispatchers
 * (vec_add / sgemm / rmsnorm / attention / reduce_sum) plus the
 * OoFloatBuf-typed vec_add_buf variant. NVIDIA twin of
 * gpu_hip_dispatch.c (+ _buf). The liboo_cuda.so binding lives in
 * gpu_cuda_dlopen.c. Cap token: GpuCap via oo_cap_require_gpu. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The launcher table typedef is in gpu.h (OoCudaKernels). */
OoCudaKernels *oo_cuda_kernels(void);
int oo_cuda_so_bind(void);
int oo_gpu_init(long long cap);

OoResS oo_gpu_cuda_vec_add(long long cap, float *a, float *b, float *c, int n) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_cuda_vec_add");
  oo_gpu_init(cap);
  if (!a || !b || !c || n <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->vec_add_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  int rc = oo_cuda_kernels()->vec_add_launch(a, b, c, n);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 vec_add MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add launch failed");
  return r;
}

OoResS oo_gpu_cuda_vec_add_buf(long long cap, OoFloatBuf a, OoFloatBuf b, OoFloatBuf c) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_cuda_vec_add_buf");
  oo_gpu_init(cap);
  if (!a.data || !b.data || !c.data) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add_buf null buf"); return r;
  }
  if (a.len <= 0 || b.len <= 0 || c.len <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add_buf zero len"); return r;
  }
  if (a.len != b.len || a.len != c.len) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add_buf length mismatch"); return r;
  }
  if (a.len > a.cap || b.len > b.cap || c.len > c.cap) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add_buf cap overflow"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->vec_add_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  int n = (int)a.len;
  int rc = oo_cuda_kernels()->vec_add_launch(a.data, b.data, c.data, n);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 vec_add_buf MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add_buf numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add_buf launch failed");
  return r;
}

OoResS oo_gpu_cuda_sgemm(long long cap, const float *a, const float *b, float *c, int m, int n, int k) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_cuda_sgemm");
  oo_gpu_init(cap);
  if (!a || !b || !c || m <= 0 || n <= 0 || k <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tsgemm invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->sgemm_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  int rc = oo_cuda_kernels()->sgemm_launch(a, b, c, m, n, k);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 sgemm MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tsgemm numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tsgemm launch failed");
  return r;
}

OoResS oo_gpu_cuda_rmsnorm(long long cap, const float *x, const float *gamma, float *out, int rows, int dim) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_cuda_rmsnorm");
  oo_gpu_init(cap);
  if (!x || !out || rows <= 0 || dim <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\trmsnorm invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->rmsnorm_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  int rc = oo_cuda_kernels()->rmsnorm_launch(x, gamma, out, rows, dim);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 rmsnorm MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\trmsnorm numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\trmsnorm launch failed");
  return r;
}

OoResS oo_gpu_cuda_attention(long long cap, const float *q, const float *k, const float *v, float *out, int seq_len, int d_head) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_cuda_attention");
  oo_gpu_init(cap);
  if (!q || !k || !v || !out || seq_len <= 0 || d_head <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tattention invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->attention_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  int rc = oo_cuda_kernels()->attention_launch(q, k, v, out, seq_len, d_head);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 attention MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tattention numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tattention launch failed");
  return r;
}

OoResS oo_gpu_cuda_reduce_sum(long long cap, const float *in, float *out, int n) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_cuda_reduce_sum");
  oo_gpu_init(cap);
  if (!in || !out || n <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\treduce_sum invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->reduce_sum_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  int rc = oo_cuda_kernels()->reduce_sum_launch(in, out, n);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 reduce_sum MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\treduce_sum numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\treduce_sum launch failed");
  return r;
}
