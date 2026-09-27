/* gpu/gpu_cuda_dispatch_flist.c — .oo List[Float] CUDA dispatchers.
 *
 * The oodac LLVM backend passes .oo flists as `ptr byval(%OoFList)`.
 * byval passes the 24-byte aggregate (on the stack), NOT a pointer —
 * so these entries take OoFList BY VALUE (the oo_flist_push convention),
 * never pointers. .oo Float is f64, so each entry converts double <->
 * float around the f32 kernels (mirroring the oo_cuda_* helpers the
 * --backend cuda emitter generates). Cap token: GpuCap. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

OoCudaKernels *oo_cuda_kernels(void);
int oo_cuda_so_bind(void);
int oo_gpu_init(long long cap);

static int oo_cuda_fl_ok(OoFList b, long long need) {
  if (!b.data || b.len <= 0 || b.len > b.cap) return 0;
  return need <= b.len;
}

static float *oo_cuda_fl_tof(const OoFList b, long long n) {
  float *f = (float *)malloc((size_t)n * sizeof(float));
  if (!f) return 0;
  for (long long i = 0; i < n; i++) f[i] = (float)b.data[i];
  return f;
}

static void oo_cuda_fl_tod(OoFList b, const float *f, long long n) {
  for (long long i = 0; i < n; i++) b.data[i] = (double)f[i];
}

OoResS oo_gpu_cuda_vec_add_flist(long long cap, OoFList a, OoFList b, OoFList c, int n) {
  OoResS r;
  float *fa, *fb, *fc;
  int rc;
  oo_cap_require_gpu(cap, "gpu_cuda_vec_add");
  oo_gpu_init(cap);
  if (n <= 0 || !oo_cuda_fl_ok(a, n) || !oo_cuda_fl_ok(b, n) || !oo_cuda_fl_ok(c, n)) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->vec_add_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  fa = oo_cuda_fl_tof(a, n); fb = oo_cuda_fl_tof(b, n); fc = (float *)malloc((size_t)n * 4);
  if (!fa || !fb || !fc) {
    free(fa); free(fb); free(fc);
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add host_alloc"); return r;
  }
  rc = oo_cuda_kernels()->vec_add_launch(fa, fb, fc, n);
  if (rc == 0) oo_cuda_fl_tod(c, fc, n);
  free(fa); free(fb); free(fc);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 vec_add MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tvec_add launch failed");
  return r;
}

OoResS oo_gpu_cuda_sgemm_flist(long long cap, OoFList a, OoFList b, OoFList c, int m, int n, int k) {
  OoResS r;
  float *fa, *fb, *fc;
  int rc;
  oo_cap_require_gpu(cap, "gpu_cuda_sgemm");
  oo_gpu_init(cap);
  if (m <= 0 || n <= 0 || k <= 0 || !oo_cuda_fl_ok(a, (long long)m * k) ||
      !oo_cuda_fl_ok(b, (long long)k * n) || !oo_cuda_fl_ok(c, (long long)m * n)) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tsgemm invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->sgemm_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  fa = oo_cuda_fl_tof(a, (long long)m * k); fb = oo_cuda_fl_tof(b, (long long)k * n);
  fc = (float *)malloc((size_t)m * n * 4);
  if (!fa || !fb || !fc) {
    free(fa); free(fb); free(fc);
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tsgemm host_alloc"); return r;
  }
  rc = oo_cuda_kernels()->sgemm_launch(fa, fb, fc, m, n, k);
  if (rc == 0) oo_cuda_fl_tod(c, fc, (long long)m * n);
  free(fa); free(fb); free(fc);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 sgemm MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tsgemm numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tsgemm launch failed");
  return r;
}

OoResS oo_gpu_cuda_rmsnorm_flist(long long cap, OoFList x, OoFList gamma, OoFList out, int rows, int dim) {
  OoResS r;
  float *fx, *fg, *fo;
  long long need;
  int rc;
  oo_cap_require_gpu(cap, "gpu_cuda_rmsnorm");
  oo_gpu_init(cap);
  need = (long long)rows * dim;
  if (rows <= 0 || dim <= 0 || !oo_cuda_fl_ok(x, need) || !oo_cuda_fl_ok(out, need) ||
      (gamma.data && !oo_cuda_fl_ok(gamma, dim))) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\trmsnorm invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->rmsnorm_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  fx = oo_cuda_fl_tof(x, need); fg = gamma.data ? oo_cuda_fl_tof(gamma, dim) : 0;
  fo = (float *)malloc((size_t)need * 4);
  if (!fx || !fo || (gamma.data && !fg)) {
    free(fx); free(fg); free(fo);
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\trmsnorm host_alloc"); return r;
  }
  rc = oo_cuda_kernels()->rmsnorm_launch(fx, fg, fo, rows, dim);
  if (rc == 0) oo_cuda_fl_tod(out, fo, need);
  free(fx); free(fg); free(fo);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 rmsnorm MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\trmsnorm numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\trmsnorm launch failed");
  return r;
}

OoResS oo_gpu_cuda_attention_flist(long long cap, OoFList q, OoFList k, OoFList v, OoFList out, int seq_len, int d_head) {
  OoResS r;
  float *fq, *fk, *fv, *fo;
  long long need;
  int rc;
  oo_cap_require_gpu(cap, "gpu_cuda_attention");
  oo_gpu_init(cap);
  need = (long long)seq_len * d_head;
  if (seq_len <= 0 || d_head <= 0 || !oo_cuda_fl_ok(q, need) || !oo_cuda_fl_ok(k, need) ||
      !oo_cuda_fl_ok(v, need) || !oo_cuda_fl_ok(out, need)) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tattention invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->attention_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  fq = oo_cuda_fl_tof(q, need); fk = oo_cuda_fl_tof(k, need); fv = oo_cuda_fl_tof(v, need);
  fo = (float *)malloc((size_t)need * 4);
  if (!fq || !fk || !fv || !fo) {
    free(fq); free(fk); free(fv); free(fo);
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tattention host_alloc"); return r;
  }
  rc = oo_cuda_kernels()->attention_launch(fq, fk, fv, fo, seq_len, d_head);
  if (rc == 0) oo_cuda_fl_tod(out, fo, need);
  free(fq); free(fk); free(fv); free(fo);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 attention MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tattention numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tattention launch failed");
  return r;
}

OoResS oo_gpu_cuda_reduce_sum_flist(long long cap, OoFList in, OoFList out, int n) {
  OoResS r;
  float *fi, fo[1];
  int rc;
  oo_cap_require_gpu(cap, "gpu_cuda_reduce_sum");
  oo_gpu_init(cap);
  if (n <= 0 || !oo_cuda_fl_ok(in, n) || !oo_cuda_fl_ok(out, 1)) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\treduce_sum invalid args"); return r;
  }
  if (!oo_cuda_so_bind() || !oo_cuda_kernels()->reduce_sum_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\tliboo_cuda.so absent"); return r;
  }
  fi = oo_cuda_fl_tof(in, n);
  if (!fi) {
    r.ok = 0; r.val = oo_str_lit("ERR\tcuda\treduce_sum host_alloc"); return r;
  }
  fo[0] = 0.0f;
  rc = oo_cuda_kernels()->reduce_sum_launch(fi, fo, n);
  if (rc == 0) out.data[0] = (double)fo[0];
  free(fi);
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit("cuda sm_89 reduce_sum MATCH"); return r; }
  if (rc == 5) { r.ok = 0; r.val = oo_str_lit("ERR\tcuda\treduce_sum numerical mismatch"); return r; }
  r.ok = 0; r.val = oo_str_lit("ERR\tcuda\treduce_sum launch failed");
  return r;
}
