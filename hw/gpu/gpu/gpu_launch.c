/* gpu/gpu_launch.c — kernel classification + dispatch table.
 * The HIP backend kernels (vec_add / sgemm / rmsnorm / attention /
 * reduce_sum / rope / stencil_3d) live in gpu_hip_dispatch.c. This
 * file owns:
 *   - the OoGpuKernelKind enum and the per-kind name table
 *   - oo_gpu_classify_kernel (name + structural marker detection)
 *   - oo_gpu_launch_kernel (the public dispatch entry point)
 * Cap token: GpuCap via oo_cap_require_gpu. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  OO_GPU_KIND_UNKNOWN = 0,
  OO_GPU_KIND_VEC_ADD,
  OO_GPU_KIND_SGEMM,
  OO_GPU_KIND_RMSNORM,
  OO_GPU_KIND_ATTENTION,
  OO_GPU_KIND_REDUCE_SUM,
  OO_GPU_KIND_ROPE,
  OO_GPU_KIND_STENCIL_3D
} OoGpuKernelKind;

/* Forward decls (defined in gpu_hip_dispatch.c). */
OoResS oo_gpu_hip_vec_add(long long cap, float *a, float *b, float *c, int n);
OoResS oo_gpu_hip_sgemm(long long cap, const float *a, const float *b, float *c, int m, int n, int k);
OoResS oo_gpu_hip_rmsnorm(long long cap, const float *x, const float *gamma, float *out, int rows, int dim);
OoResS oo_gpu_hip_attention(long long cap, const float *q, const float *k, const float *v, float *out, int seq_len, int d_head);
OoResS oo_gpu_hip_reduce_sum(long long cap, const float *in, float *out, int n);
OoResS oo_gpu_hip_rope(long long cap, const float *in, const float *cos_val, const float *sin_val, float *out, int seq_len, int dim);
OoResS oo_gpu_hip_stencil_3d(long long cap, const float *in, float *out, int nx, int ny, int nz, float c0, float c1);

static int oo_gpu_kname_in(const char *k, const char *const *ids) {
  int i;
  if (!k || !ids) return 0;
  for (i = 0; ids[i]; i++) {
    if (strcmp(k, ids[i]) == 0) return 1;
  }
  return 0;
}

static const char *const oo_gpu_ids_vec_add[] = {
  "vec_add", "k_vec_add", "oo_k_vec_add", "oo_hip_vec_add", "k_add", NULL
};
static const char *const oo_gpu_ids_sgemm[] = {
  "sgemm", "k_sgemm", "oo_k_sgemm_tiled", "matmul", "k_matmul", NULL
};
static const char *const oo_gpu_ids_rmsnorm[] = {
  "rmsnorm", "rms_norm", "k_rmsnorm", "oo_k_rmsnorm", NULL
};
static const char *const oo_gpu_ids_attention[] = {
  "attention", "flash_attention", "k_attention", "oo_k_attention", "k_attn", NULL
};
static const char *const oo_gpu_ids_reduce[] = {
  "reduce_sum", "k_reduce_sum", "oo_k_reduce_sum", NULL
};
static const char *const oo_gpu_ids_rope[] = {
  "rope", "k_rope", "oo_k_rope", NULL
};
static const char *const oo_gpu_ids_stencil[] = {
  "stencil_3d", "k_stencil_3d", "oo_k_stencil_3d", NULL
};

OoGpuKernelKind oo_gpu_classify_kernel(const char *kname, const char *code, long long code_len) {
  /* Phase 1: Specific kernel name matching using exact strcmp */
  if (kname && kname[0] != '\0' && strcmp(kname, "k_main") != 0 &&
      strcmp(kname, "k_kernel") != 0 && strcmp(kname, "k_loop") != 0 &&
      strcmp(kname, "k_fn") != 0 && strcmp(kname, "default") != 0) {
    if (oo_gpu_kname_in(kname, oo_gpu_ids_vec_add)) return OO_GPU_KIND_VEC_ADD;
    if (oo_gpu_kname_in(kname, oo_gpu_ids_sgemm)) return OO_GPU_KIND_SGEMM;
    if (oo_gpu_kname_in(kname, oo_gpu_ids_rmsnorm)) return OO_GPU_KIND_RMSNORM;
    if (oo_gpu_kname_in(kname, oo_gpu_ids_attention)) return OO_GPU_KIND_ATTENTION;
    if (oo_gpu_kname_in(kname, oo_gpu_ids_reduce)) return OO_GPU_KIND_REDUCE_SUM;
    if (oo_gpu_kname_in(kname, oo_gpu_ids_rope)) return OO_GPU_KIND_ROPE;
    if (oo_gpu_kname_in(kname, oo_gpu_ids_stencil)) return OO_GPU_KIND_STENCIL_3D;
  }

  /* Phase 2: Code / Descriptor Structural Marker Parsing */
  if (code && code_len > 0) {
    if (strstr(code, "oo_k_sgemm") || strstr(code, "s_a[16]") || strstr(code, "s_b[16]") ||
        strstr(code, "tiled_sgemm") || strstr(code, "TILED_GEMM") || strstr(code, "fmaf(s_a") ||
        strstr(code, "kernel_descriptor:sgemm") || strstr(code, "op:sgemm")) {
      return OO_GPU_KIND_SGEMM;
    }
    if (strstr(code, "oo_k_attention") || strstr(code, "m_prev") || strstr(code, "flash_attention") ||
        strstr(code, "FLASH_ATTENTION") || strstr(code, "kernel_descriptor:attention") ||
        strstr(code, "op:attention") || (strstr(code, "q_row") && strstr(code, "head_dim"))) {
      return OO_GPU_KIND_ATTENTION;
    }
    if (strstr(code, "oo_k_rmsnorm") || strstr(code, "hip_warp_reduce_sum") ||
        strstr(code, "s_warp_sums") || strstr(code, "s_inv_rms") || strstr(code, "RMS_NORM") ||
        strstr(code, "rms_norm_wave32") || strstr(code, "kernel_descriptor:rmsnorm") ||
        strstr(code, "op:rmsnorm")) {
      return OO_GPU_KIND_RMSNORM;
    }
    if (strstr(code, "oo_k_rope") || strstr(code, "theta_base") || strstr(code, "pair_idx") ||
        strstr(code, "token_pos") || strstr(code, "ROPE") ||
        strstr(code, "kernel_descriptor:rope") || strstr(code, "op:rope")) {
      return OO_GPU_KIND_ROPE;
    }
    if (strstr(code, "oo_k_stencil_3d") || strstr(code, "sum_neighbors") ||
        strstr(code, "c0 * center") || strstr(code, "STENCIL_3D") ||
        strstr(code, "kernel_descriptor:stencil_3d") || strstr(code, "op:stencil_3d")) {
      return OO_GPU_KIND_STENCIL_3D;
    }
    if (strstr(code, "oo_k_reduce_sum") || strstr(code, "atomicAdd(out_val") ||
        strstr(code, "atomicAdd(out,") || strstr(code, "REDUCE_SUM") ||
        strstr(code, "kernel_descriptor:reduce_sum") || strstr(code, "op:reduce_sum")) {
      return OO_GPU_KIND_REDUCE_SUM;
    }
    if (strstr(code, "oo_k_vec_add") || strstr(code, "oo_k_vec_fma") ||
        strstr(code, "ADD_GLOBAL_F32") || strstr(code, "c[i] = a[i] + b[i]") ||
        strstr(code, "kernel_descriptor:vec_add") || strstr(code, "op:vec_add")) {
      return OO_GPU_KIND_VEC_ADD;
    }
  }

  /* Fallback Phase: specific kname tables again */
  if (oo_gpu_kname_in(kname, oo_gpu_ids_vec_add)) return OO_GPU_KIND_VEC_ADD;
  if (oo_gpu_kname_in(kname, oo_gpu_ids_sgemm)) return OO_GPU_KIND_SGEMM;
  if (oo_gpu_kname_in(kname, oo_gpu_ids_rmsnorm)) return OO_GPU_KIND_RMSNORM;
  if (oo_gpu_kname_in(kname, oo_gpu_ids_attention)) return OO_GPU_KIND_ATTENTION;
  if (oo_gpu_kname_in(kname, oo_gpu_ids_reduce)) return OO_GPU_KIND_REDUCE_SUM;
  if (oo_gpu_kname_in(kname, oo_gpu_ids_rope)) return OO_GPU_KIND_ROPE;
  if (oo_gpu_kname_in(kname, oo_gpu_ids_stencil)) return OO_GPU_KIND_STENCIL_3D;

  return OO_GPU_KIND_UNKNOWN;
}

OoResS oo_gpu_launch_kernel(long long cap, OoStr target, OoStr kernel_name, OoStr code,
                            int gx, int gy, int gz, int bx, int by, int bz,
                            void **kernel_args, int arg_count) {
  OoResS r; const char *tg, *kname;
  (void)by; (void)bz;
  oo_cap_require_gpu(cap, "gpu_launch_kernel");
  oo_gpu_init(cap);
  if (gx <= 0 || bx <= 0) { r.ok = 0; r.val = oo_str_lit("invalid grid dimensions"); return r; }
  tg = target.data ? target.data : "";
  kname = kernel_name.data ? kernel_name.data : "";

  if (strncmp(tg, "hip", 3) != 0 && strncmp(tg, "rocm", 4) != 0) {
    r.ok = 0; r.val = oo_str_lit("gpu residual: target must be hip: or rocm:");
    return r;
  }
  if (!g_hip_ok) {
    r.ok = 0; r.val = oo_str_lit("gpu residual: HIP/ROCm runtime absent");
    return r;
  }

  OoGpuKernelKind kind = oo_gpu_classify_kernel(kname, code.data, code.len);

  /* 1. Vector Addition / Elementwise Add */
  if (kind == OO_GPU_KIND_VEC_ADD) {
    if (arg_count < 3 || !kernel_args || !kernel_args[0] || !kernel_args[1] || !kernel_args[2]) {
      r.ok = 0; r.val = oo_str_lit("invalid vec_add args"); return r;
    }
    float *a = (float*)kernel_args[0];
    float *b = (float*)kernel_args[1];
    float *c = (float*)kernel_args[2];
    int n = (arg_count >= 4 && kernel_args[3]) ? *(int*)kernel_args[3] : (gx * bx);
    if (n <= 0) { r.ok = 0; r.val = oo_str_lit("invalid vec_add count"); return r; }
    return oo_gpu_hip_vec_add(cap, a, b, c, n);
  }

  /* 2. SGEMM / Matrix Multiplication */
  if (kind == OO_GPU_KIND_SGEMM) {
    if (arg_count < 3 || !kernel_args || !kernel_args[0] || !kernel_args[1] || !kernel_args[2]) {
      r.ok = 0; r.val = oo_str_lit("invalid sgemm args"); return r;
    }
    const float *a = (const float*)kernel_args[0];
    const float *b = (const float*)kernel_args[1];
    float *c = (float*)kernel_args[2];
    int m = (arg_count >= 4 && kernel_args[3]) ? *(int*)kernel_args[3] : gx;
    int n = (arg_count >= 5 && kernel_args[4]) ? *(int*)kernel_args[4] : bx;
    int k = (arg_count >= 6 && kernel_args[5]) ? *(int*)kernel_args[5] : bx;
    if (m <= 0 || n <= 0 || k <= 0) { r.ok = 0; r.val = oo_str_lit("invalid sgemm dimensions"); return r; }
    return oo_gpu_hip_sgemm(cap, a, b, c, m, n, k);
  }

  /* 3. RMSNorm */
  if (kind == OO_GPU_KIND_RMSNORM) {
    if (arg_count < 3 || !kernel_args || !kernel_args[0] || !kernel_args[2]) {
      r.ok = 0; r.val = oo_str_lit("invalid rmsnorm args"); return r;
    }
    const float *x = (const float*)kernel_args[0];
    const float *gamma = (const float*)kernel_args[1];
    float *out = (float*)kernel_args[2];
    int rows = (arg_count >= 4 && kernel_args[3]) ? *(int*)kernel_args[3] : gx;
    int dim = (arg_count >= 5 && kernel_args[4]) ? *(int*)kernel_args[4] : bx;
    if (rows <= 0 || dim <= 0) { r.ok = 0; r.val = oo_str_lit("invalid rmsnorm dimensions"); return r; }
    return oo_gpu_hip_rmsnorm(cap, x, gamma, out, rows, dim);
  }

  /* 4. Attention / Flash Attention */
  if (kind == OO_GPU_KIND_ATTENTION) {
    if (arg_count < 4 || !kernel_args || !kernel_args[0] || !kernel_args[1] || !kernel_args[2] || !kernel_args[3]) {
      r.ok = 0; r.val = oo_str_lit("invalid attention args"); return r;
    }
    const float *q = (const float*)kernel_args[0];
    const float *k = (const float*)kernel_args[1];
    const float *v = (const float*)kernel_args[2];
    float *out = (float*)kernel_args[3];
    int seq_len = (arg_count >= 5 && kernel_args[4]) ? *(int*)kernel_args[4] : gx;
    int d_head = (arg_count >= 6 && kernel_args[5]) ? *(int*)kernel_args[5] : bx;
    if (seq_len <= 0 || d_head <= 0) { r.ok = 0; r.val = oo_str_lit("invalid attention dimensions"); return r; }
    if (d_head > 256) { r.ok = 0; r.val = oo_str_lit("invalid attention args: d_head exceeds maximum bound of 256"); return r; }
    return oo_gpu_hip_attention(cap, q, k, v, out, seq_len, d_head);
  }

  /* 5. Reduce Sum */
  if (kind == OO_GPU_KIND_REDUCE_SUM) {
    if (arg_count < 2 || !kernel_args || !kernel_args[0] || !kernel_args[1]) {
      r.ok = 0; r.val = oo_str_lit("invalid reduce_sum args"); return r;
    }
    const float *in = (const float*)kernel_args[0];
    float *out = (float*)kernel_args[1];
    int n = (arg_count >= 3 && kernel_args[2]) ? *(int*)kernel_args[2] : (gx * bx);
    if (n <= 0) { r.ok = 0; r.val = oo_str_lit("invalid reduce_sum count"); return r; }
    return oo_gpu_hip_reduce_sum(cap, in, out, n);
  }

  /* 6. RoPE */
  if (kind == OO_GPU_KIND_ROPE) {
    if (arg_count < 4 || !kernel_args || !kernel_args[0] || !kernel_args[1] || !kernel_args[2] || !kernel_args[3]) {
      r.ok = 0; r.val = oo_str_lit("invalid rope args"); return r;
    }
    const float *in = (const float*)kernel_args[0];
    const float *cos_val = (const float*)kernel_args[1];
    const float *sin_val = (const float*)kernel_args[2];
    float *out = (float*)kernel_args[3];
    int seq_len = (arg_count >= 5 && kernel_args[4]) ? *(int*)kernel_args[4] : gx;
    int dim = (arg_count >= 6 && kernel_args[5]) ? *(int*)kernel_args[5] : bx;
    if (seq_len <= 0 || dim <= 0 || (dim % 2) != 0) {
      r.ok = 0; r.val = oo_str_lit("invalid rope dimensions"); return r;
    }
    return oo_gpu_hip_rope(cap, in, cos_val, sin_val, out, seq_len, dim);
  }

  /* 7. Stencil 3D */
  if (kind == OO_GPU_KIND_STENCIL_3D) {
    if (arg_count < 2 || !kernel_args || !kernel_args[0] || !kernel_args[1]) {
      r.ok = 0; r.val = oo_str_lit("invalid stencil_3d args"); return r;
    }
    const float *in = (const float*)kernel_args[0];
    float *out = (float*)kernel_args[1];
    int nx = (arg_count >= 3 && kernel_args[2]) ? *(int*)kernel_args[2] : gx;
    int ny = (arg_count >= 4 && kernel_args[3]) ? *(int*)kernel_args[3] : (gy > 0 ? gy : 1);
    int nz = (arg_count >= 5 && kernel_args[4]) ? *(int*)kernel_args[4] : (bz > 0 ? bz : 1);
    float c0 = (arg_count >= 6 && kernel_args[5]) ? *(float*)kernel_args[5] : 1.0f;
    float c1 = (arg_count >= 7 && kernel_args[6]) ? *(float*)kernel_args[6] : 0.1f;
    if (nx <= 0 || ny <= 0 || nz <= 0) {
      r.ok = 0; r.val = oo_str_lit("invalid stencil dimensions"); return r;
    }
    (void)gz;
    return oo_gpu_hip_stencil_3d(cap, in, out, nx, ny, nz, c0, c1);
  }

  /* Unrecognized kernel: Fail closed */
  {
    char err_buf[128];
    snprintf(err_buf, sizeof(err_buf), "gpu launch failed: unrecognized kernel '%s'", kname);
    r.ok = 0;
    r.val = oo_str_lit(err_buf);
    return r;
  }
}
