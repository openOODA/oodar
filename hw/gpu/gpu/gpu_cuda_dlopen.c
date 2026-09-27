/* gpu/gpu_cuda_dlopen.c — dynamic-loader side of the liboo_cuda.so backend.
 * NVIDIA twin of gpu_hip_dlopen.c. Owns the search path (OODA_CUDA_LIB
 * env, OODA_HOME, cwd, /proc/self/exe, LD_LIBRARY_PATH fallback) and
 * the dlsym of the five launchers. gpu_cuda.c (the orchestrator) is
 * the only public caller; the rest of the runtime reaches the
 * launchers through gpu_cuda_dispatch.c. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>

static void *g_oo_cuda_so = NULL;
static OoCudaKernels g_cuda_k;
static int g_cuda_so_bound = 0;
static pthread_mutex_t g_cuda_so_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Shared launchers — exposed to gpu_cuda_dispatch.c. */
OoCudaKernels *oo_cuda_kernels(void) { return &g_cuda_k; }

static void *oo_dlopen_oo_cuda(void) {
  void *h = NULL;

  /* 1. Check explicit environment variable OODA_CUDA_LIB */
  const char *env_cuda_lib = getenv("OODA_CUDA_LIB");
  if (env_cuda_lib && env_cuda_lib[0] != '\0') {
    h = dlopen(env_cuda_lib, RTLD_LAZY | RTLD_LOCAL);
    if (h) return h;
  }

  /* 2. Check OODA_HOME environment variable */
  const char *env_ooda_home = getenv("OODA_HOME");
  if (env_ooda_home && env_ooda_home[0] != '\0') {
    char cand[PATH_MAX];
    snprintf(cand, sizeof(cand), "%s/ooda/liboo_cuda.so", env_ooda_home);
    h = dlopen(cand, RTLD_LAZY | RTLD_LOCAL);
    if (h) return h;
    snprintf(cand, sizeof(cand), "%s/liboo_cuda.so", env_ooda_home);
    h = dlopen(cand, RTLD_LAZY | RTLD_LOCAL);
    if (h) return h;
  }

  /* 3. Check relative to CWD (prefer ./liboo_cuda.so when cwd is ooda/) */
  const char *cwd_cands[] = {
    "./liboo_cuda.so",
    "./ooda/liboo_cuda.so",
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
      snprintf(cand, sizeof(cand), "%s/liboo_cuda.so", exe);
      h = dlopen(cand, RTLD_LAZY | RTLD_LOCAL);
      if (h) return h;
      snprintf(cand, sizeof(cand), "%s/../liboo_cuda.so", exe);
      h = dlopen(cand, RTLD_LAZY | RTLD_LOCAL);
      if (h) return h;
    }
  }

  /* 5. Fallback to LD_LIBRARY_PATH and default system resolution */
  h = dlopen("liboo_cuda.so", RTLD_LAZY | RTLD_LOCAL);
  if (h) return h;

  return NULL;
}

int oo_cuda_so_bind(void) {
  pthread_mutex_lock(&g_cuda_so_mutex);
  if (g_cuda_so_bound) {
    int ok = (g_cuda_k.vec_add_launch != NULL);
    pthread_mutex_unlock(&g_cuda_so_mutex);
    return ok;
  }
  g_oo_cuda_so = oo_dlopen_oo_cuda();
  if (!g_oo_cuda_so) {
    g_cuda_so_bound = 1;
    pthread_mutex_unlock(&g_cuda_so_mutex);
    return 0;
  }
  g_cuda_k.vec_add_launch = (int (*)(const float *, const float *, float *, int))dlsym(g_oo_cuda_so, "oo_cuda_vec_add_launch");
  g_cuda_k.sgemm_launch = (int (*)(const float *, const float *, float *, int, int, int))dlsym(g_oo_cuda_so, "oo_cuda_sgemm_launch");
  g_cuda_k.rmsnorm_launch = (int (*)(const float *, const float *, float *, int, int))dlsym(g_oo_cuda_so, "oo_cuda_rmsnorm_launch");
  g_cuda_k.attention_launch = (int (*)(const float *, const float *, const float *, float *, int, int))dlsym(g_oo_cuda_so, "oo_cuda_attention_launch");
  g_cuda_k.reduce_sum_launch = (int (*)(const float *, float *, int))dlsym(g_oo_cuda_so, "oo_cuda_reduce_sum_launch");
  g_cuda_so_bound = 1;
  int ok = (g_cuda_k.vec_add_launch != NULL);
  pthread_mutex_unlock(&g_cuda_so_mutex);
  return ok;
}
