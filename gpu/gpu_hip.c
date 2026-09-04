#include "gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>

typedef struct {
  int (*vec_add_launch)(const float *, const float *, float *, int);
  int (*sgemm_launch)(const float *, const float *, float *, int, int, int);
  int (*rmsnorm_launch)(const float *, const float *, float *, int, int);
  int (*attention_launch)(const float *, const float *, const float *, float *, int, int);
  int (*reduce_sum_launch)(const float *, float *, int);
  int (*rope_launch)(const float *, const float *, const float *, float *, int, int);
  int (*stencil_3d_launch)(const float *, float *, int, int, int, float, float);
} OoHipKernels;

static void *g_oo_hip_so = NULL;
static OoHipKernels g_hip_k;
static int g_hip_so_bound = 0;
static pthread_mutex_t g_hip_so_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *oo_dlopen_oo_hip(void) {
  void *h = NULL;

  /* 1. Check explicit environment variable OODA_HIP_LIB */
  const char *env_hip_lib = getenv("OODA_HIP_LIB");
  if (env_hip_lib && env_hip_lib[0] != '\0') {
    h = dlopen(env_hip_lib, RTLD_LAZY | RTLD_LOCAL);
    if (h) return h;
  }

  /* 2. Check OODA_HOME environment variable */
  const char *env_ooda_home = getenv("OODA_HOME");
  if (env_ooda_home && env_ooda_home[0] != '\0') {
    char cand[PATH_MAX];
    snprintf(cand, sizeof(cand), "%s/ooda/liboo_hip.so", env_ooda_home);
    h = dlopen(cand, RTLD_LAZY | RTLD_LOCAL);
    if (h) return h;
    snprintf(cand, sizeof(cand), "%s/liboo_hip.so", env_ooda_home);
    h = dlopen(cand, RTLD_LAZY | RTLD_LOCAL);
    if (h) return h;
  }

  /* 3. Check relative to CWD (prefer ./liboo_hip.so when cwd is ooda/) */
  const char *cwd_cands[] = {
    "./liboo_hip.so",
    "./ooda/liboo_hip.so",
    NULL
  };
  for (int i = 0; cwd_cands[i]; i++) {
    h = dlopen(cwd_cands[i], RTLD_LAZY | RTLD_LOCAL);
    if (h) return h;
  }

  /* 4. Check relative to the running executable */
  char exe[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if (n > 0) {
    exe[n] = '\0';
    char *slash = strrchr(exe, '/');
    if (slash) {
      *slash = '\0';
      char cand[PATH_MAX];
      snprintf(cand, sizeof(cand), "%s/liboo_hip.so", exe);
      h = dlopen(cand, RTLD_LAZY | RTLD_LOCAL);
      if (h) return h;
      snprintf(cand, sizeof(cand), "%s/../liboo_hip.so", exe);
      h = dlopen(cand, RTLD_LAZY | RTLD_LOCAL);
      if (h) return h;
    }
  }

  /* 5. Fallback to LD_LIBRARY_PATH and default system resolution */
  h = dlopen("liboo_hip.so", RTLD_LAZY | RTLD_LOCAL);
  if (h) return h;

  return NULL;
}

static int oo_hip_so_bind(void) {
  pthread_mutex_lock(&g_hip_so_mutex);
  if (g_hip_so_bound) {
    int ok = (g_hip_k.vec_add_launch != NULL);
    pthread_mutex_unlock(&g_hip_so_mutex);
    return ok;
  }
  g_oo_hip_so = oo_dlopen_oo_hip();
  if (!g_oo_hip_so) {
    g_hip_so_bound = 1;
    pthread_mutex_unlock(&g_hip_so_mutex);
    return 0;
  }
  g_hip_k.vec_add_launch = (int (*)(const float *, const float *, float *, int))dlsym(g_oo_hip_so, "oo_hip_vec_add_launch");
  g_hip_k.sgemm_launch = (int (*)(const float *, const float *, float *, int, int, int))dlsym(g_oo_hip_so, "oo_hip_sgemm_launch");
  g_hip_k.rmsnorm_launch = (int (*)(const float *, const float *, float *, int, int))dlsym(g_oo_hip_so, "oo_hip_rmsnorm_launch");
  g_hip_k.attention_launch = (int (*)(const float *, const float *, const float *, float *, int, int))dlsym(g_oo_hip_so, "oo_hip_attention_launch");
  g_hip_k.reduce_sum_launch = (int (*)(const float *, float *, int))dlsym(g_oo_hip_so, "oo_hip_reduce_sum_launch");
  g_hip_k.rope_launch = (int (*)(const float *, const float *, const float *, float *, int, int))dlsym(g_oo_hip_so, "oo_hip_rope_launch");
  g_hip_k.stencil_3d_launch = (int (*)(const float *, float *, int, int, int, float, float))dlsym(g_oo_hip_so, "oo_hip_stencil_3d_launch");
  g_hip_so_bound = 1;
  int ok = (g_hip_k.vec_add_launch != NULL);
  pthread_mutex_unlock(&g_hip_so_mutex);
  return ok;
}

OoResS oo_gpu_hip_vec_add(long long cap, float *a, float *b, float *c, int n) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_hip_vec_add");
  oo_gpu_init(cap);
  if (!a || !b || !c || n <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tvec_add invalid args"); return r;
  }
  if (!oo_hip_so_bind() || !g_hip_k.vec_add_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tliboo_hip.so absent"); return r;
  }
  int rc = g_hip_k.vec_add_launch(a, b, c, n);
  if (rc == 0) {
    r.ok = 1; r.val = oo_str_lit("hip gfx1100 vec_add MATCH"); return r;
  }
  if (rc == 5) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tvec_add numerical mismatch"); return r;
  }
  r.ok = 0; r.val = oo_str_lit("ERR\thip\tvec_add launch failed");
  return r;
}

OoResS oo_gpu_hip_sgemm(long long cap, const float *a, const float *b, float *c, int m, int n, int k) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_hip_sgemm");
  oo_gpu_init(cap);
  if (!a || !b || !c || m <= 0 || n <= 0 || k <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tsgemm invalid args"); return r;
  }
  if (!oo_hip_so_bind() || !g_hip_k.sgemm_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tliboo_hip.so absent"); return r;
  }
  int rc = g_hip_k.sgemm_launch(a, b, c, m, n, k);
  if (rc == 0) {
    r.ok = 1; r.val = oo_str_lit("hip gfx1100 sgemm MATCH"); return r;
  }
  if (rc == 5) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tsgemm numerical mismatch"); return r;
  }
  r.ok = 0; r.val = oo_str_lit("ERR\thip\tsgemm launch failed");
  return r;
}

OoResS oo_gpu_hip_rmsnorm(long long cap, const float *x, const float *gamma, float *out, int rows, int dim) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_hip_rmsnorm");
  oo_gpu_init(cap);
  if (!x || !out || rows <= 0 || dim <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\trmsnorm invalid args"); return r;
  }
  if (!oo_hip_so_bind() || !g_hip_k.rmsnorm_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tliboo_hip.so absent"); return r;
  }
  int rc = g_hip_k.rmsnorm_launch(x, gamma, out, rows, dim);
  if (rc == 0) {
    r.ok = 1; r.val = oo_str_lit("hip gfx1100 rmsnorm MATCH"); return r;
  }
  if (rc == 5) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\trmsnorm numerical mismatch"); return r;
  }
  r.ok = 0; r.val = oo_str_lit("ERR\thip\trmsnorm launch failed");
  return r;
}

OoResS oo_gpu_hip_attention(long long cap, const float *q, const float *k, const float *v, float *out, int seq_len, int d_head) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_hip_attention");
  oo_gpu_init(cap);
  if (!q || !k || !v || !out || seq_len <= 0 || d_head <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tattention invalid args"); return r;
  }
  if (d_head > 256) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tattention d_head exceeds maximum bound 256"); return r;
  }
  if (!oo_hip_so_bind() || !g_hip_k.attention_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tliboo_hip.so absent"); return r;
  }
  int rc = g_hip_k.attention_launch(q, k, v, out, seq_len, d_head);
  if (rc == 0) {
    r.ok = 1; r.val = oo_str_lit("hip gfx1100 attention MATCH"); return r;
  }
  if (rc == 5) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tattention numerical mismatch"); return r;
  }
  r.ok = 0; r.val = oo_str_lit("ERR\thip\tattention launch failed");
  return r;
}

OoResS oo_gpu_hip_reduce_sum(long long cap, const float *in, float *out, int n) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_hip_reduce_sum");
  oo_gpu_init(cap);
  if (!in || !out || n <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\treduce_sum invalid args"); return r;
  }
  if (!oo_hip_so_bind() || !g_hip_k.reduce_sum_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tliboo_hip.so absent"); return r;
  }
  int rc = g_hip_k.reduce_sum_launch(in, out, n);
  if (rc == 0) {
    r.ok = 1; r.val = oo_str_lit("hip gfx1100 reduce_sum MATCH"); return r;
  }
  if (rc == 5) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\treduce_sum numerical mismatch"); return r;
  }
  r.ok = 0; r.val = oo_str_lit("ERR\thip\treduce_sum launch failed");
  return r;
}

OoResS oo_gpu_hip_rope(long long cap, const float *in, const float *cos_val, const float *sin_val, float *out, int seq_len, int dim) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_hip_rope");
  oo_gpu_init(cap);
  if (!in || !cos_val || !sin_val || !out || seq_len <= 0 || dim <= 0 || (dim % 2) != 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\trope invalid args"); return r;
  }
  if (!oo_hip_so_bind() || !g_hip_k.rope_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tliboo_hip.so absent"); return r;
  }
  int rc = g_hip_k.rope_launch(in, cos_val, sin_val, out, seq_len, dim);
  if (rc == 0) {
    r.ok = 1; r.val = oo_str_lit("hip gfx1100 rope MATCH"); return r;
  }
  if (rc == 5) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\trope numerical mismatch"); return r;
  }
  r.ok = 0; r.val = oo_str_lit("ERR\thip\trope launch failed");
  return r;
}

OoResS oo_gpu_hip_stencil_3d(long long cap, const float *in, float *out, int nx, int ny, int nz, float c0, float c1) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_hip_stencil_3d");
  oo_gpu_init(cap);
  if (!in || !out || nx <= 0 || ny <= 0 || nz <= 0) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tstencil_3d invalid args"); return r;
  }
  if (!oo_hip_so_bind() || !g_hip_k.stencil_3d_launch) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tliboo_hip.so absent"); return r;
  }
  int rc = g_hip_k.stencil_3d_launch(in, out, nx, ny, nz, c0, c1);
  if (rc == 0) {
    r.ok = 1; r.val = oo_str_lit("hip gfx1100 stencil_3d MATCH"); return r;
  }
  if (rc == 5) {
    r.ok = 0; r.val = oo_str_lit("ERR\thip\tstencil_3d numerical mismatch"); return r;
  }
  r.ok = 0; r.val = oo_str_lit("ERR\thip\tstencil_3d launch failed");
  return r;
}

static int oo_hip_kname_is(const char *n, long long nlen, const char *lit) {
  size_t L;
  if (!n || !lit || nlen < 0) return 0;
  L = strlen(lit);
  if ((size_t)nlen != L) return 0;
  return strncmp(n, lit, (size_t)nlen) == 0;
}

static int oo_hip_kname_in(const char *n, long long nlen, const char *const *ids) {
  int i;
  if (!ids) return 0;
  for (i = 0; ids[i]; i++) {
    if (oo_hip_kname_is(n, nlen, ids[i])) return 1;
  }
  return 0;
}

static const char *const oo_hip_ids_vec_add[] = {
  "vec_add", "k_vec_add", "oo_k_vec_add", "oo_hip_vec_add", "k_add", NULL
};
static const char *const oo_hip_ids_sgemm[] = {
  "sgemm", "k_sgemm", "oo_k_sgemm_tiled", "matmul", "k_matmul", NULL
};
static const char *const oo_hip_ids_rmsnorm[] = {
  "rmsnorm", "rms_norm", "k_rmsnorm", "oo_k_rmsnorm", NULL
};
static const char *const oo_hip_ids_attention[] = {
  "attention", "flash_attention", "k_attention", "oo_k_attention", "k_attn", NULL
};

OoResS oo_gpu_hip_try_launch(long long cap, OoStr shader) {
  OoResS r;
  const char *p;
  const char *name;
  long long len;
  long long nlen;
  oo_cap_require_gpu(cap, "gpu_launch");
  oo_gpu_init(cap);
  p = shader.data ? shader.data : "";
  len = shader.len < 0 ? 0 : shader.len;
  name = p;
  nlen = len;
  if (len >= 4 && strncmp(p, "hip:", 4) == 0) {
    name = p + 4;
    nlen = len - 4;
  } else if (len >= 5 && strncmp(p, "rocm:", 5) == 0) {
    name = p + 5;
    nlen = len - 5;
  } else {
    r.ok = 0;
    r.val = oo_str_lit("gpu residual: unknown shader directive");
    return r;
  }

  if (oo_hip_kname_in(name, nlen, oo_hip_ids_vec_add)) {
    float ha[64], hb[64], hc[64];
    int i;
    for (i = 0; i < 64; i++) {
      ha[i] = (float)i;
      hb[i] = 2.0f * (float)i;
      hc[i] = 0.0f;
    }
    return oo_gpu_hip_vec_add(cap, ha, hb, hc, 64);
  }

  if (oo_hip_kname_in(name, nlen, oo_hip_ids_sgemm)) {
    const int m = 8, n = 8, k = 8;
    size_t sa = (size_t)m * (size_t)k * sizeof(float);
    size_t sb = (size_t)k * (size_t)n * sizeof(float);
    size_t sc = (size_t)m * (size_t)n * sizeof(float);
    float *A = (float *)malloc(sa);
    float *B = (float *)malloc(sb);
    float *C = (float *)malloc(sc);
    int i;
    if (!A || !B || !C) {
      free(A); free(B); free(C);
      r.ok = 0;
      r.val = oo_str_lit("ERR\thip\tsgemm host_alloc");
      return r;
    }
    for (i = 0; i < m * k; i++) A[i] = 1.0f;
    for (i = 0; i < k * n; i++) B[i] = 2.0f;
    r = oo_gpu_hip_sgemm(cap, A, B, C, m, n, k);
    free(A); free(B); free(C);
    return r;
  }

  if (oo_hip_kname_in(name, nlen, oo_hip_ids_rmsnorm)) {
    float x[32], gamma[32], out[32];
    int i;
    for (i = 0; i < 32; i++) { x[i] = 1.0f; gamma[i] = 1.0f; out[i] = 0.0f; }
    return oo_gpu_hip_rmsnorm(cap, x, gamma, out, 1, 32);
  }

  if (oo_hip_kname_in(name, nlen, oo_hip_ids_attention)) {
    float q[32], k[32], v[32], out[32];
    int i;
    for (i = 0; i < 32; i++) { q[i] = 0.1f; k[i] = 0.1f; v[i] = 0.1f; out[i] = 0.0f; }
    return oo_gpu_hip_attention(cap, q, k, v, out, 4, 8);
  }

  r.ok = 0;
  r.val = oo_str_lit("gpu launch failed: unrecognized kernel");
  return r;
}
