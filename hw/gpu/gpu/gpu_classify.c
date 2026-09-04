/* gpu/gpu_classify.c — kernel name + structural-marker classification.
 * Phase 1 matches the kname against per-kind exact-match ID tables.
 * Phase 2 scans the kernel code / descriptor for known structural
 * markers (tiled_sgemm, kernel_descriptor:*, oo_k_*, etc).
 * Phase 3 falls back to the ID tables for kname-only matches.
 * Owned: OoGpuKernelKind enum, oo_gpu_kname_in, oo_gpu_classify_kernel,
 * the 7 ID tables. Orchestrator: gpu_launch.c (which calls
 * oo_gpu_classify_kernel). This file is included before gpu_launch.c
 * in the umbrella so the enum and the function are both visible. */
#include "../gpu.h"
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

static int oo_gpu_kname_in(const char *k, const char *const *ids) {
  int i;
  if (!k || !ids) return 0;
  for (i = 0; ids[i]; i++) {
    if (strcmp(k, ids[i]) == 0) return 1;
  }
  return 0;
}

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
