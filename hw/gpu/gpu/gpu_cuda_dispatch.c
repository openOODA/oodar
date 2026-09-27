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

static int oo_cuda_kname_is(const char *n, long long nlen, const char *lit) {
  size_t L;
  if (!n || !lit) return 0;
  L = strlen(lit);
  if ((size_t)nlen != L) return 0;
  return strncmp(n, lit, (size_t)nlen) == 0;
}

static int oo_cuda_kname_in(const char *n, long long nlen, const char *const *ids) {
  int i;
  if (!ids) return 0;
  for (i = 0; ids[i]; i++) {
    if (oo_cuda_kname_is(n, nlen, ids[i])) return 1;
  }
  return 0;
}

static const char *const oo_cuda_ids_vec_add[] = {
  "vec_add", "k_vec_add", "oo_k_cuda_vec_add", "oo_cuda_vec_add", "k_add", NULL
};
static const char *const oo_cuda_ids_sgemm[] = {
  "sgemm", "k_sgemm", "oo_k_cuda_sgemm", "matmul", "k_matmul", NULL
};
static const char *const oo_cuda_ids_rmsnorm[] = {
  "rmsnorm", "rms_norm", "k_rmsnorm", "oo_k_cuda_rmsnorm", NULL
};
static const char *const oo_cuda_ids_attention[] = {
  "attention", "flash_attention", "k_attn", "oo_k_cuda_attn", "k_attention", NULL
};
static const char *const oo_cuda_ids_reduce[] = {
  "reduce_sum", "reduce", "k_reduce", "oo_k_cuda_reduce", NULL
};

OoResS oo_gpu_cuda_try_launch_dispatch(long long cap, OoStr shader) {
  OoResS r;
  const char *p;
  const char *name;
  long long len;
  long long nlen;
  p = shader.data ? shader.data : "";
  len = shader.len < 0 ? 0 : shader.len;
  name = p;
  nlen = len;
  if (len >= 5 && strncmp(p, "cuda:", 5) == 0) {
    name = p + 5;
    nlen = len - 5;
  } else {
    r.ok = 0;
    r.val = oo_str_lit("gpu residual: unknown shader directive (want cuda:<kernel>)");
    return r;
  }

  /* NEVER shadow cap with 0 (see the HIP twin for why). */
  if (oo_cuda_kname_in(name, nlen, oo_cuda_ids_vec_add)) {
    float ha[64], hb[64], hc[64];
    int i;
    for (i = 0; i < 64; i++) {
      ha[i] = (float)i;
      hb[i] = 2.0f * (float)i;
      hc[i] = 0.0f;
    }
    return oo_gpu_cuda_vec_add(cap, ha, hb, hc, 64);
  }

  if (oo_cuda_kname_in(name, nlen, oo_cuda_ids_sgemm)) {
    float A[64], B[64], C[64];
    int i;
    for (i = 0; i < 64; i++) { A[i] = 1.0f; B[i] = 2.0f; C[i] = 0.0f; }
    return oo_gpu_cuda_sgemm(cap, A, B, C, 8, 8, 8);
  }

  if (oo_cuda_kname_in(name, nlen, oo_cuda_ids_rmsnorm)) {
    float x[32], gamma[32], out[32];
    int i;
    for (i = 0; i < 32; i++) { x[i] = 1.0f; gamma[i] = 1.0f; out[i] = 0.0f; }
    return oo_gpu_cuda_rmsnorm(cap, x, gamma, out, 1, 32);
  }

  if (oo_cuda_kname_in(name, nlen, oo_cuda_ids_attention)) {
    float q[32], k[32], v[32], out[32];
    int i;
    for (i = 0; i < 32; i++) { q[i] = 0.1f; k[i] = 0.1f; v[i] = 0.1f; out[i] = 0.0f; }
    return oo_gpu_cuda_attention(cap, q, k, v, out, 4, 8);
  }

  if (oo_cuda_kname_in(name, nlen, oo_cuda_ids_reduce)) {
    float in[256], out[1];
    int i;
    for (i = 0; i < 256; i++) in[i] = 1.0f;
    out[0] = 0.0f;
    return oo_gpu_cuda_reduce_sum(cap, in, out, 256);
  }

  r.ok = 0;
  r.val = oo_str_lit("gpu launch failed: unrecognized kernel");
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
