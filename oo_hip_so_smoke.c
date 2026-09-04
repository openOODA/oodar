/* Host verification smoke test: dlopen liboo_hip.so and verify compute kernels. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <math.h>

static void *oo_dlopen_oo_hip(void) {
  void *h = NULL;

  const char *env_hip_lib = getenv("OODA_HIP_LIB");
  if (env_hip_lib && env_hip_lib[0] != '\0') {
    h = dlopen(env_hip_lib, RTLD_LAZY);
    if (h) return h;
  }

  const char *env_ooda_home = getenv("OODA_HOME");
  if (env_ooda_home && env_ooda_home[0] != '\0') {
    char cand[PATH_MAX];
    snprintf(cand, sizeof(cand), "%s/ooda/liboo_hip.so", env_ooda_home);
    h = dlopen(cand, RTLD_LAZY);
    if (h) return h;
    snprintf(cand, sizeof(cand), "%s/liboo_hip.so", env_ooda_home);
    h = dlopen(cand, RTLD_LAZY);
    if (h) return h;
  }

  h = dlopen("./liboo_hip.so", RTLD_LAZY);
  if (h) return h;

  char exe[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if (n > 0) {
    exe[n] = '\0';
    char *slash = strrchr(exe, '/');
    if (slash) {
      *slash = '\0';
      char cand[PATH_MAX];
      snprintf(cand, sizeof(cand), "%s/liboo_hip.so", exe);
      h = dlopen(cand, RTLD_LAZY);
      if (h) return h;
      snprintf(cand, sizeof(cand), "%s/../liboo_hip.so", exe);
      h = dlopen(cand, RTLD_LAZY);
      if (h) return h;
      snprintf(cand, sizeof(cand), "%s/../../liboo_hip.so", exe);
      h = dlopen(cand, RTLD_LAZY);
      if (h) return h;
    }
  }

  h = dlopen("liboo_hip.so", RTLD_LAZY);
  if (h) return h;
  return NULL;
}

int main(void) {
  void *h = oo_dlopen_oo_hip();
  if (!h) {
    fprintf(stderr, "ERR\thip_so\t%s\n", dlerror());
    return 1;
  }

  /* 1. Vector Add */
  int (*fn_vec_add)(const float *, const float *, float *, int) =
      (int (*)(const float *, const float *, float *, int))dlsym(h, "oo_hip_vec_add_launch");
  if (!fn_vec_add) {
    fprintf(stderr, "ERR\thip_so\tmissing oo_hip_vec_add_launch\n");
    return 1;
  }
  float a[64], b[64], c[64];
  for (int i = 0; i < 64; i++) {
    a[i] = (float)i;
    b[i] = 2.0f * (float)i;
    c[i] = 0.0f;
  }
  if (fn_vec_add(a, b, c, 64) != 0) {
    fprintf(stderr, "ERR\thip_so\tvec_add failed\n");
    return 1;
  }
  for (int i = 0; i < 64; i++) {
    if (fabsf(c[i] - 3.0f * (float)i) > 1e-5f) {
      fprintf(stderr, "ERR\thip_so\tvec_add mismatch at %d: got %f\n", i, c[i]);
      return 1;
    }
  }
  printf("hip_so_vec_add: MATCH n=64 gfx1100\n");

  /* 2. LDS Tiled SGEMM */
  int (*fn_sgemm)(const float *, const float *, float *, int, int, int) =
      (int (*)(const float *, const float *, float *, int, int, int))dlsym(h, "oo_hip_sgemm_launch");
  if (!fn_sgemm) {
    fprintf(stderr, "ERR\thip_so\tmissing oo_hip_sgemm_launch\n");
    return 1;
  }
  int M = 32, N = 32, K = 32;
  float *matA = (float*)malloc(M * K * sizeof(float));
  float *matB = (float*)malloc(K * N * sizeof(float));
  float *matC = (float*)malloc(M * N * sizeof(float));
  for (int i = 0; i < M * K; i++) matA[i] = 1.0f;
  for (int i = 0; i < K * N; i++) matB[i] = 2.0f;
  if (fn_sgemm(matA, matB, matC, M, N, K) != 0) {
    fprintf(stderr, "ERR\thip_so\tsgemm failed\n");
    return 1;
  }
  for (int i = 0; i < M * N; i++) {
    if (fabsf(matC[i] - 64.0f) > 1e-4f) {
      fprintf(stderr, "ERR\thip_so\tsgemm mismatch at %d: got %f, expected 64.0\n", i, matC[i]);
      return 1;
    }
  }
  printf("hip_so_sgemm: MATCH 32x32x32 gfx1100\n");
  free(matA); free(matB); free(matC);

  /* 3. Wave32 RMSNorm */
  int (*fn_rmsnorm)(const float *, const float *, float *, int, int) =
      (int (*)(const float *, const float *, float *, int, int))dlsym(h, "oo_hip_rmsnorm_launch");
  if (!fn_rmsnorm) {
    fprintf(stderr, "ERR\thip_so\tmissing oo_hip_rmsnorm_launch\n");
    return 1;
  }
  int rows = 4, dim = 64;
  float *x = (float*)malloc(rows * dim * sizeof(float));
  float *gamma = (float*)malloc(dim * sizeof(float));
  float *out_rms = (float*)malloc(rows * dim * sizeof(float));
  for (int i = 0; i < rows * dim; i++) x[i] = 1.0f;
  for (int i = 0; i < dim; i++) gamma[i] = 1.0f;
  if (fn_rmsnorm(x, gamma, out_rms, rows, dim) != 0) {
    fprintf(stderr, "ERR\thip_so\trmsnorm failed\n");
    return 1;
  }
  for (int i = 0; i < rows * dim; i++) {
    if (fabsf(out_rms[i] - 1.0f) > 1e-3f) {
      fprintf(stderr, "ERR\thip_so\trmsnorm mismatch at %d: got %f, expected 1.0\n", i, out_rms[i]);
      return 1;
    }
  }
  printf("hip_so_rmsnorm: MATCH 4x64 gfx1100\n");
  free(x); free(gamma); free(out_rms);

  /* 4. Fused Attention (Online Softmax) */
  int (*fn_attn)(const float *, const float *, const float *, float *, int, int) =
      (int (*)(const float *, const float *, const float *, float *, int, int))dlsym(h, "oo_hip_attention_launch");
  if (!fn_attn) {
    fprintf(stderr, "ERR\thip_so\tmissing oo_hip_attention_launch\n");
    return 1;
  }
  int seq_len = 16, d_head = 32;
  float *q = (float*)malloc(seq_len * d_head * sizeof(float));
  float *k = (float*)malloc(seq_len * d_head * sizeof(float));
  float *v = (float*)malloc(seq_len * d_head * sizeof(float));
  float *out_attn = (float*)malloc(seq_len * d_head * sizeof(float));
  for (int i = 0; i < seq_len * d_head; i++) {
    q[i] = 0.5f;
    k[i] = 0.5f;
    v[i] = 2.0f;
  }
  if (fn_attn(q, k, v, out_attn, seq_len, d_head) != 0) {
    fprintf(stderr, "ERR\thip_so\tattention failed\n");
    return 1;
  }
  for (int i = 0; i < seq_len * d_head; i++) {
    if (fabsf(out_attn[i] - 2.0f) > 1e-3f) {
      fprintf(stderr, "ERR\thip_so\tattention mismatch at %d: got %f, expected 2.0\n", i, out_attn[i]);
      return 1;
    }
  }
  printf("hip_so_attention: MATCH 16x32 gfx1100\n");
  free(q); free(k); free(v); free(out_attn);

  /* 5. Parallel Reduction (Sum) */
  int (*fn_reduce)(const float *, float *, int) =
      (int (*)(const float *, float *, int))dlsym(h, "oo_hip_reduce_sum_launch");
  if (!fn_reduce) {
    fprintf(stderr, "ERR\thip_so\tmissing oo_hip_reduce_sum_launch\n");
    return 1;
  }
  int n_red = 256;
  float *in_red = (float*)malloc(n_red * sizeof(float));
  float out_red = 0.0f;
  for (int i = 0; i < n_red; i++) in_red[i] = 1.0f;
  if (fn_reduce(in_red, &out_red, n_red) != 0) {
    fprintf(stderr, "ERR\thip_so\treduce_sum failed\n");
    return 1;
  }
  if (fabsf(out_red - 256.0f) > 1e-3f) {
    fprintf(stderr, "ERR\thip_so\treduce_sum mismatch: got %f, expected 256.0\n", out_red);
    return 1;
  }
  printf("hip_so_reduce_sum: MATCH n=256 gfx1100\n");
  free(in_red);

  /* 6. Rotary Position Embedding (RoPE) */
  int (*fn_rope)(const float *, const float *, const float *, float *, int, int) =
      (int (*)(const float *, const float *, const float *, float *, int, int))dlsym(h, "oo_hip_rope_launch");
  if (!fn_rope) {
    fprintf(stderr, "ERR\thip_so\tmissing oo_hip_rope_launch\n");
    return 1;
  }
  int rope_seq = 8, rope_dim = 16;
  float *in_rope = (float*)malloc(rope_seq * rope_dim * sizeof(float));
  float *cos_rope = (float*)malloc(rope_seq * (rope_dim / 2) * sizeof(float));
  float *sin_rope = (float*)malloc(rope_seq * (rope_dim / 2) * sizeof(float));
  float *out_rope = (float*)malloc(rope_seq * rope_dim * sizeof(float));
  for (int i = 0; i < rope_seq * rope_dim; i++) in_rope[i] = 1.0f;
  for (int i = 0; i < rope_seq * (rope_dim / 2); i++) {
    cos_rope[i] = 1.0f; // cos(0) = 1
    sin_rope[i] = 0.0f; // sin(0) = 0
  }
  if (fn_rope(in_rope, cos_rope, sin_rope, out_rope, rope_seq, rope_dim) != 0) {
    fprintf(stderr, "ERR\thip_so\trope failed\n");
    return 1;
  }
  for (int i = 0; i < rope_seq * rope_dim; i++) {
    if (fabsf(out_rope[i] - 1.0f) > 1e-4f) {
      fprintf(stderr, "ERR\thip_so\trope mismatch at %d: got %f, expected 1.0\n", i, out_rope[i]);
      return 1;
    }
  }
  printf("hip_so_rope: MATCH 8x16 gfx1100\n");
  free(in_rope); free(cos_rope); free(sin_rope); free(out_rope);

  /* 7. 3D 7-Point Stencil */
  int (*fn_stencil)(const float *, float *, int, int, int, float, float) =
      (int (*)(const float *, float *, int, int, int, float, float))dlsym(h, "oo_hip_stencil_3d_launch");
  if (!fn_stencil) {
    fprintf(stderr, "ERR\thip_so\tmissing oo_hip_stencil_3d_launch\n");
    return 1;
  }
  int nx = 16, ny = 16, nz = 16;
  size_t total_voxels = nx * ny * nz;
  float *in_st = (float*)malloc(total_voxels * sizeof(float));
  float *out_st = (float*)malloc(total_voxels * sizeof(float));
  for (size_t i = 0; i < total_voxels; i++) in_st[i] = 1.0f;
  if (fn_stencil(in_st, out_st, nx, ny, nz, 2.0f, 0.5f) != 0) {
    fprintf(stderr, "ERR\thip_so\tstencil_3d failed\n");
    return 1;
  }
  // Inside boundary: c0*1.0 + c1*(6*1.0) = 2.0 + 3.0 = 5.0
  int interior_idx = 8 * (nx * ny) + 8 * nx + 8;
  if (fabsf(out_st[interior_idx] - 5.0f) > 1e-3f) {
    fprintf(stderr, "ERR\thip_so\tstencil_3d interior mismatch: got %f, expected 5.0\n", out_st[interior_idx]);
    return 1;
  }
  printf("hip_so_stencil_3d: MATCH 16x16x16 gfx1100\n");
  free(in_st); free(out_st);

  printf("hip_so_all_kernels: ALL_PASS gfx1100\n");
  return 0;
}
