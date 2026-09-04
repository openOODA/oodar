/* gpu/gpu_hip.c — orchestrator for the liboo_hip.so dynamic backend.
 * The oo_dlopen_oo_hip / oo_hip_so_bind table lives in gpu_hip_dlopen.c;
 * the actual kernel dispatchers (oo_gpu_hip_vec_add / sgemm / rmsnorm /
 * attention / reduce_sum / rope / stencil_3d) live in gpu_hip_dispatch.c.
 * This file owns the bind-once logic, the public load/unload surface,
 * and the oo_gpu_hip_avail / oo_gpu_hip_try_launch entry points.
 * Cap token: GpuCap via oo_cap_require_gpu. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

extern int oo_hip_so_bind(void);
OoResS oo_gpu_hip_try_launch_dispatch(long long cap, OoStr shader);

int oo_gpu_hip_load(void) {
  /* Triggers the lazy bind of liboo_hip.so. Returns 1 on success, 0 on
   * failure. The bind itself is idempotent and mutex-guarded. */
  return oo_hip_so_bind() ? 1 : 0;
}

int oo_gpu_hip_unload(void) {
  /* liboo_hip.so is dlopen'd with RTLD_LOCAL; there is no portable way
   * to dlclose without affecting other consumers. The product surface
   * is "load once, use forever"; unload is a no-op that returns 1 to
   * keep the symmetric load/unload API. */
  return 1;
}

int oo_gpu_hip_avail(void) {
  return oo_hip_so_bind() ? 1 : 0;
}

OoResS oo_gpu_hip_try_launch(long long cap, OoStr shader) {
  oo_cap_require_gpu(cap, "gpu_launch");
  oo_gpu_init(cap);
  return oo_gpu_hip_try_launch_dispatch(cap, shader);
}
