/* gpu/gpu.c — orchestrator: HIP/ROCm init, device probe, sync.
 * The buffer pool lives in gpu_pool.c, the memory-copy surface in
 * gpu_mem.c, streams/events in gpu_stream.c, the kernel-launch
 * classification + dispatch in gpu_launch.c, and the HIP backend
 * (liboo_hip.so binding and the oo_gpu_hip_* dispatch) in gpu_hip*.c.
 *
 * All shared state (g_hip, g_gpu_*, g_pool_*, g_stream_*, g_event_*,
 * g_pending_copies, g_vram_*) lives in this orchestrator as extern
 * (visible to the satellite files). The mutex is global; every public
 * entry point takes it. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <dlfcn.h>
#include <pthread.h>

#define OO_GPU_POOL_BINS 32
#define OO_GPU_MAX_PENDING_COPIES 1024

typedef struct OoGpuBlock {
  void *gpu_ptr;
  size_t capacity_bytes;
  int bin_index;
  int is_in_use;
  int in_flight_copies;
  struct OoGpuBlock *next_free;
  struct OoGpuBlock *all_next;
} OoGpuBlock;

typedef struct {
  OoGpuBlock *blk;
  long long stream_handle;
  int active;
} OoGpuPendingCopy;

/* The liboo_hip.so launcher table. Defined in gpu_hip_dlopen.c, but the
 * typedef is here so gpu_hip_dispatch.c and gpu_hip.c can use it
 * without redefining. */
typedef struct {
  int (*vec_add_launch)(const float *, const float *, float *, int);
  int (*sgemm_launch)(const float *, const float *, float *, int, int, int);
  int (*rmsnorm_launch)(const float *, const float *, float *, int, int);
  int (*attention_launch)(const float *, const float *, const float *, float *, int, int);
  int (*reduce_sum_launch)(const float *, float *, int);
  int (*rope_launch)(const float *, const float *, const float *, float *, int, int);
  int (*stencil_3d_launch)(const float *, float *, int, int, int, float, float);
} OoHipKernels;

typedef struct {
  const char* (*hipGetErrorString)(int);
  const char* (*hipGetErrorName)(int);
  int (*hipGetLastError)(void);
  int (*hipPeekAtLastError)(void);
  int (*hipGetDeviceCount)(int *);
  int (*hipGetDevice)(int *);
  int (*hipSetDevice)(int);
  int (*hipDeviceSynchronize)(void);
  int (*hipDeviceReset)(void);
  int (*hipMalloc)(void **, size_t);
  int (*hipFree)(void *);
  int (*hipMemcpy)(void *, const void *, size_t, int);
  int (*hipMemcpyAsync)(void *, const void *, size_t, int, void *);
  int (*hipStreamCreateWithFlags)(void **, unsigned int);
  int (*hipStreamDestroy)(void *);
  int (*hipStreamSynchronize)(void *);
  int (*hipStreamQuery)(void *);
  int (*hipEventCreateWithFlags)(void **, unsigned int);
  int (*hipEventDestroy)(void *);
  int (*hipEventRecord)(void *, void *);
  int (*hipEventSynchronize)(void *);
  int (*hipEventElapsedTime)(float *, void *, void *);
} OoHipApi;

OoHipApi g_hip;
void *g_hip_lib;
int g_hip_ok = 0;
int g_gpu_initialized = 0;
pthread_mutex_t g_gpu_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Pool state (used by gpu_pool.c, defined here) */
OoGpuBlock *g_pool_bins[OO_GPU_POOL_BINS];
OoGpuBlock *g_pool_all_head;
OoGpuBlock *g_handle_blocks[OO_GPU_MAX_BUFFERS];
size_t g_vram_total_allocated;
size_t g_vram_total_active;

/* Stream / event / pending-copy state (used by gpu_stream.c and gpu_mem.c) */
void *g_stream_handles[OO_GPU_MAX_STREAMS];
void *g_event_handles[OO_GPU_MAX_EVENTS];
OoGpuPendingCopy g_pending_copies[OO_GPU_MAX_PENDING_COPIES];

const char* oo_hip_err_str(int rc) {
  if (g_hip.hipGetErrorString) {
    const char *s = g_hip.hipGetErrorString(rc);
    if (s) return s;
  }
  return "Unknown ROCm/HIP error";
}

int oo_gpu_size_to_bin(size_t bytes) {
  int bin = 0;
  size_t cur = 64;
  while (cur < bytes && bin < OO_GPU_POOL_BINS - 1) {
    cur <<= 1;
    bin++;
  }
  return bin;
}

size_t oo_gpu_bin_to_size(int bin) {
  return ((size_t)64) << bin;
}

void *oo_gpu_dlopen_hip(void) {
  void *h;
  const char *cands[] = {
    "/opt/rocm/lib/libamdhip64.so.7",
    "/opt/rocm/lib/libamdhip64.so",
    "/opt/rocm/core-10.0/lib/libamdhip64.so.7",
    "libamdhip64.so.7",
    "libamdhip64.so",
    "libamdhip64.so.6",
    NULL
  };
  for (int i = 0; cands[i]; i++) {
    h = dlopen(cands[i], RTLD_LAZY | RTLD_LOCAL);
    if (h) return h;
  }
  return NULL;
}

int oo_gpu_hip_available(void) {
  return g_hip_ok;
}

int oo_gpu_init(long long cap) {
  oo_cap_require_gpu(cap, "gpu_init");
  pthread_mutex_lock(&g_gpu_mutex);
  if (g_gpu_initialized) {
    int already = g_hip_ok;
    pthread_mutex_unlock(&g_gpu_mutex);
    return already ? 1 : 0;
  }

  g_hip_lib = oo_gpu_dlopen_hip();
  if (g_hip_lib) {
    g_hip.hipGetErrorString = (const char* (*)(int))dlsym(g_hip_lib, "hipGetErrorString");
    g_hip.hipGetErrorName = (const char* (*)(int))dlsym(g_hip_lib, "hipGetErrorName");
    g_hip.hipGetLastError = (int (*)(void))dlsym(g_hip_lib, "hipGetLastError");
    g_hip.hipPeekAtLastError = (int (*)(void))dlsym(g_hip_lib, "hipPeekAtLastError");
    g_hip.hipGetDeviceCount = (int (*)(int *))dlsym(g_hip_lib, "hipGetDeviceCount");
    g_hip.hipGetDevice = (int (*)(int *))dlsym(g_hip_lib, "hipGetDevice");
    g_hip.hipSetDevice = (int (*)(int))dlsym(g_hip_lib, "hipSetDevice");
    g_hip.hipDeviceSynchronize = (int (*)(void))dlsym(g_hip_lib, "hipDeviceSynchronize");
    g_hip.hipDeviceReset = (int (*)(void))dlsym(g_hip_lib, "hipDeviceReset");
    g_hip.hipMalloc = (int (*)(void **, size_t))dlsym(g_hip_lib, "hipMalloc");
    g_hip.hipFree = (int (*)(void *))dlsym(g_hip_lib, "hipFree");
    g_hip.hipMemcpy = (int (*)(void *, const void *, size_t, int))dlsym(g_hip_lib, "hipMemcpy");
    g_hip.hipMemcpyAsync = (int (*)(void *, const void *, size_t, int, void *))dlsym(g_hip_lib, "hipMemcpyAsync");
    g_hip.hipStreamCreateWithFlags = (int (*)(void **, unsigned int))dlsym(g_hip_lib, "hipStreamCreateWithFlags");
    g_hip.hipStreamDestroy = (int (*)(void *))dlsym(g_hip_lib, "hipStreamDestroy");
    g_hip.hipStreamSynchronize = (int (*)(void *))dlsym(g_hip_lib, "hipStreamSynchronize");
    g_hip.hipStreamQuery = (int (*)(void *))dlsym(g_hip_lib, "hipStreamQuery");
    g_hip.hipEventCreateWithFlags = (int (*)(void **, unsigned int))dlsym(g_hip_lib, "hipEventCreateWithFlags");
    g_hip.hipEventDestroy = (int (*)(void *))dlsym(g_hip_lib, "hipEventDestroy");
    g_hip.hipEventRecord = (int (*)(void *, void *))dlsym(g_hip_lib, "hipEventRecord");
    g_hip.hipEventSynchronize = (int (*)(void *))dlsym(g_hip_lib, "hipEventSynchronize");
    g_hip.hipEventElapsedTime = (int (*)(float *, void *, void *))dlsym(g_hip_lib, "hipEventElapsedTime");

    if (g_hip.hipMalloc && g_hip.hipFree && g_hip.hipMemcpy && g_hip.hipGetErrorString &&
        g_hip.hipStreamCreateWithFlags && g_hip.hipMemcpyAsync &&
        g_hip.hipEventCreateWithFlags && g_hip.hipEventElapsedTime &&
        g_hip.hipStreamDestroy && g_hip.hipStreamSynchronize &&
        g_hip.hipEventDestroy && g_hip.hipEventRecord && g_hip.hipEventSynchronize) {
      g_hip_ok = 1;
    }
  }

  memset(g_pool_bins, 0, sizeof(g_pool_bins));
  memset(g_handle_blocks, 0, sizeof(g_handle_blocks));
  memset(g_stream_handles, 0, sizeof(g_stream_handles));
  memset(g_event_handles, 0, sizeof(g_event_handles));
  memset(g_pending_copies, 0, sizeof(g_pending_copies));
  g_gpu_initialized = 1;
  int ok = g_hip_ok;
  pthread_mutex_unlock(&g_gpu_mutex);
  if (!ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_init: HIP/ROCm runtime absent; failing closed\n");
  }
  return ok;
}

OoResS oo_gpu_probe_device(long long cap, int device_id) {
  OoResS r; char buf[128]; int ndev = 0;
  oo_cap_require_gpu(cap, "gpu_probe_device");
  oo_gpu_init(cap);
  if (!g_hip_ok) {
    r.ok = 0;
    r.val = oo_str_lit("gpu residual: HIP/ROCm runtime absent");
    return r;
  }
  if (g_hip.hipGetDeviceCount) g_hip.hipGetDeviceCount(&ndev);
  snprintf(buf, sizeof(buf), "AMD HIP/ROCm gfx1100 Device #%d (count=%d)", device_id, ndev);
  r.ok = 1; r.val = oo_str_lit(buf);
  return r;
}

OoResS oo_gpu_sync(long long cap) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_sync");
  oo_gpu_init(cap);
  if (!g_hip_ok) {
    r.ok = 0;
    r.val = oo_str_lit("gpu residual: HIP/ROCm runtime absent");
    return r;
  }
  int sync_ok = 1;
  int hip_err = 0;
  if (g_hip.hipDeviceSynchronize) {
    int rc = g_hip.hipDeviceSynchronize();
    if (rc != OO_HIP_SUCCESS) {
      sync_ok = 0;
      hip_err = rc;
    }
  }

  pthread_mutex_lock(&g_gpu_mutex);
  for (int i = 0; i < OO_GPU_MAX_PENDING_COPIES; i++) {
    if (g_pending_copies[i].active) {
      if (g_pending_copies[i].blk && g_pending_copies[i].blk->in_flight_copies > 0) {
        g_pending_copies[i].blk->in_flight_copies--;
      }
      g_pending_copies[i].active = 0;
      g_pending_copies[i].blk = NULL;
      g_pending_copies[i].stream_handle = 0;
    }
  }
  pthread_mutex_unlock(&g_gpu_mutex);

  if (!sync_ok) {
    char err_buf[128];
    snprintf(err_buf, sizeof(err_buf), "hip sync failed: %s", oo_hip_err_str(hip_err));
    r.ok = 0;
    r.val = oo_str_lit(err_buf);
    return r;
  }
  r.ok = 1;
  r.val = oo_str_lit("gpu-synced");
  return r;
}
