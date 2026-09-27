/* gpu/gpu_cuda.c — orchestrator for the liboo_cuda.so dynamic backend.
 * NVIDIA twin of gpu_hip.c. Owns the CUDA availability probe
 * (libcuda.so.1 dlopen, independent of the HIP probe in gpu.c so
 * gpu.c stays under the 256-line cap) plus the public load/unload
 * surface. Cap token: GpuCap via oo_cap_require_gpu. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>

extern int oo_cuda_so_bind(void);

static int g_cuda_ok = -1;
static pthread_mutex_t g_cuda_mutex = PTHREAD_MUTEX_INITIALIZER;

int oo_gpu_cuda_available(void) {
  pthread_mutex_lock(&g_cuda_mutex);
  if (g_cuda_ok < 0) {
    const char *cands[] = {
      "libcuda.so.1",
      "/usr/lib64/libcuda.so.1",
      "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
      NULL
    };
    g_cuda_ok = 0;
    for (int i = 0; cands[i]; i++) {
      void *h = dlopen(cands[i], RTLD_LAZY | RTLD_LOCAL);
      if (h) { g_cuda_ok = 1; break; }
    }
  }
  int ok = g_cuda_ok;
  pthread_mutex_unlock(&g_cuda_mutex);
  return ok;
}

int oo_gpu_cuda_load(void) {
  /* Triggers the lazy bind of liboo_cuda.so. Returns 1 on success. */
  return oo_cuda_so_bind() ? 1 : 0;
}

int oo_gpu_cuda_unload(void) {
  /* Same "load once, use forever" posture as the HIP backend; unload
   * is a no-op returning 1 to keep the symmetric API. */
  return 1;
}
