/* gpu/gpu_hip_dlopen.c — dynamic-loader side of the liboo_hip.so backend.
 * Owns the search-path (OODA_HIP_LIB env, OODA_HOME, cwd, /proc/self/exe,
 * LD_LIBRARY_PATH fallback) and the dlsym of the seven launchers.
 * gpu_hip.c (the orchestrator) is the only public caller; the rest of
 * the runtime reaches the launchers through gpu_hip_dispatch.c. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>

/* OoHipKernels typedef lives in gpu.c (the orchestrator). */

static void *g_oo_hip_so = NULL;
static OoHipKernels g_hip_k;
static int g_hip_so_bound = 0;
static pthread_mutex_t g_hip_so_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Shared launchers — exposed to gpu_hip_dispatch.c. */
OoHipKernels *oo_hip_kernels(void) { return &g_hip_k; }

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

int oo_hip_so_bind(void) {
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
