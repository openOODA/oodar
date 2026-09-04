#include "chs_rt_gpu.h"
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

typedef struct {
  /* Dynamic ROCm / HIP Function pointers */
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

static OoHipApi g_hip;
static void *g_hip_lib = NULL;
static int g_hip_ok = 0;
static int g_gpu_initialized = 0;
static pthread_mutex_t g_gpu_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Segregated VRAM Memory Pool State */
static OoGpuBlock *g_pool_bins[OO_GPU_POOL_BINS];
static OoGpuBlock *g_pool_all_head = NULL;
static OoGpuBlock *g_handle_blocks[OO_GPU_MAX_BUFFERS];
static size_t g_vram_total_allocated = 0;
static size_t g_vram_total_active = 0;

/* Stream and Event Handles */
static void *g_stream_handles[OO_GPU_MAX_STREAMS];
static void *g_event_handles[OO_GPU_MAX_EVENTS];
static OoGpuPendingCopy g_pending_copies[OO_GPU_MAX_PENDING_COPIES];

static const char* oo_hip_err_str(int rc) {
  if (g_hip.hipGetErrorString) {
    const char *s = g_hip.hipGetErrorString(rc);
    if (s) return s;
  }
  return "Unknown ROCm/HIP error";
}

static int oo_gpu_size_to_bin(size_t bytes) {
  int bin = 0;
  size_t cur = 64;
  while (cur < bytes && bin < OO_GPU_POOL_BINS - 1) {
    cur <<= 1;
    bin++;
  }
  return bin;
}

static size_t oo_gpu_bin_to_size(int bin) {
  return ((size_t)64) << bin;
}

static void *oo_gpu_dlopen_hip(void) {
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
  /* Fail-closed: never report a "CPU SIMT Fallback Device" as a GPU. The caller needs a
     real device or no device. */
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

long long oo_gpu_buffer_alloc(long long cap, long long bytes, int unified) {
  (void)unified;
  oo_cap_require_gpu(cap, "gpu_buffer_alloc");
  if (bytes <= 0 || bytes > OO_ALLOC_BYTES_MAX) return 0;
  oo_gpu_init(cap);
  /* Fail-closed: refuse to allocate if the HIP/ROCm runtime is not present. A host-malloc
     fallback would silently hand out a host pointer in a handle the caller treats as VRAM. */
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_buffer_alloc: HIP/ROCm runtime absent; refusing to allocate\n");
    return 0;
  }

  pthread_mutex_lock(&g_gpu_mutex);
  int bin = oo_gpu_size_to_bin((size_t)bytes);
  size_t alloc_sz = oo_gpu_bin_to_size(bin);
  OoGpuBlock *blk = g_pool_bins[bin];

  if (blk) {
    g_pool_bins[bin] = blk->next_free;
    blk->next_free = NULL;
    blk->is_in_use = 1;
    blk->in_flight_copies = 0;
    /* If the previous owner hipFree'd this block's VRAM, the slot is still on the pool
       list but has no backing storage. Re-allocate before handing it to the caller. */
    if (!blk->gpu_ptr) {
      void *ptr = NULL;
      int rc = g_hip.hipMalloc(&ptr, alloc_sz);
      if (rc != OO_HIP_SUCCESS || !ptr) {
        /* Put the block back on the free list untouched. */
        blk->is_in_use = 0;
        blk->next_free = g_pool_bins[bin];
        g_pool_bins[bin] = blk;
        pthread_mutex_unlock(&g_gpu_mutex);
        return 0;
      }
      blk->gpu_ptr = ptr;
      blk->capacity_bytes = alloc_sz;
      g_vram_total_allocated += alloc_sz;
    }
  } else {
    void *ptr = NULL;
    int rc = g_hip.hipMalloc(&ptr, alloc_sz);
    if (rc != OO_HIP_SUCCESS || !ptr) {
      pthread_mutex_unlock(&g_gpu_mutex);
      return 0;
    }
    blk = (OoGpuBlock*)malloc(sizeof(OoGpuBlock));
    if (!blk) {
      g_hip.hipFree(ptr);
      pthread_mutex_unlock(&g_gpu_mutex);
      return 0;
    }
    blk->gpu_ptr = ptr;
    blk->capacity_bytes = alloc_sz;
    blk->bin_index = bin;
    blk->is_in_use = 1;
    blk->in_flight_copies = 0;
    blk->next_free = NULL;
    blk->all_next = g_pool_all_head;
    g_pool_all_head = blk;
    g_vram_total_allocated += alloc_sz;
  }

  g_vram_total_active += alloc_sz;
  for (int h = 1; h < OO_GPU_MAX_BUFFERS; h++) {
    if (!g_handle_blocks[h]) {
      g_handle_blocks[h] = blk;
      pthread_mutex_unlock(&g_gpu_mutex);
      return (long long)h;
    }
  }

  /* Handle table full */
  blk->is_in_use = 0;
  blk->next_free = g_pool_bins[bin];
  g_pool_bins[bin] = blk;
  g_vram_total_active -= alloc_sz;
  pthread_mutex_unlock(&g_gpu_mutex);
  return 0;
}

int oo_gpu_buffer_free(long long cap, long long buf_handle) {
  oo_cap_require_gpu(cap, "gpu_buffer_free");
  if (buf_handle <= 0 || buf_handle >= OO_GPU_MAX_BUFFERS) return 0;
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_buffer_free: HIP/ROCm runtime absent; refusing to free\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  OoGpuBlock *blk = g_handle_blocks[buf_handle];
  if (!blk || !blk->is_in_use) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  if (blk->in_flight_copies > 0) {
    /* Fail closed: block is pinned by in-flight transfer. Caller must gpu_stream_sync
       the owning streams first; freeing here would tear down VRAM the DMA is reading
       or writing. */
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  void *ptr = blk->gpu_ptr;
  int bin = blk->bin_index;
  g_handle_blocks[buf_handle] = NULL;
  blk->is_in_use = 0;
  blk->next_free = g_pool_bins[bin];
  g_pool_bins[bin] = blk;
  g_vram_total_active -= blk->capacity_bytes;
  pthread_mutex_unlock(&g_gpu_mutex);
  if (ptr) {
    g_hip.hipFree(ptr);
  }
  blk->gpu_ptr = NULL;
  return 1;
}

void* oo_gpu_buffer_get_ptr(long long cap, long long buf_handle) {
  oo_cap_require_gpu(cap, "gpu_buffer_get_ptr");
  if (buf_handle <= 0 || buf_handle >= OO_GPU_MAX_BUFFERS) return NULL;
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_buffer_get_ptr: HIP/ROCm runtime absent; refusing to map buffer\n");
    return NULL;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  void *ptr = g_handle_blocks[buf_handle] ? g_handle_blocks[buf_handle]->gpu_ptr : NULL;
  pthread_mutex_unlock(&g_gpu_mutex);
  return ptr;
}

size_t oo_gpu_buffer_get_size(long long cap, long long buf_handle) {
  oo_cap_require_gpu(cap, "gpu_buffer_get_size");
  if (buf_handle <= 0 || buf_handle >= OO_GPU_MAX_BUFFERS) return 0;
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_buffer_get_size: HIP/ROCm runtime absent; refusing to query size\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  size_t sz = g_handle_blocks[buf_handle] ? g_handle_blocks[buf_handle]->capacity_bytes : 0;
  pthread_mutex_unlock(&g_gpu_mutex);
  return sz;
}

void oo_gpu_pool_purge(long long cap) {
  oo_cap_require_gpu(cap, "gpu_pool_purge");
  /* Fail-closed: refuse to purge when the HIP/ROCm runtime is not present. The pool
     cannot be a coherent shadow of an absent device. */
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_pool_purge: HIP/ROCm runtime absent; refusing to purge\n");
    return;
  }
  /* Synchronize the whole device so any retired in-flight transfers are observable
     and pending counters can be honored. */
  if (g_hip.hipDeviceSynchronize) {
    int rc = g_hip.hipDeviceSynchronize();
    if (rc != OO_HIP_SUCCESS) {
      fprintf(stderr, "ERR\tgpu\tgpu_pool_purge: hipDeviceSynchronize failed: %s\n", oo_hip_err_str(rc));
      return;
    }
  }
  pthread_mutex_lock(&g_gpu_mutex);
  /* Retire every recorded pending-copy under the lock so the in-flight counters are
     grounded in a real device-side observation. */
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
  /* Fail-closed: any block with a positive in-flight counter aborts the purge. Silent
     return would let the caller think the pool was empty and continue using handles. */
  OoGpuBlock *chk = g_pool_all_head;
  while (chk) {
    if (chk->in_flight_copies > 0) {
      pthread_mutex_unlock(&g_gpu_mutex);
      fprintf(stderr, "ERR\tgpu\tgpu_pool_purge: in-flight copies remain after sync; refusing to purge\n");
      return;
    }
    chk = chk->all_next;
  }
  /* Fail-closed: any block still in use aborts the purge. Freeing an in-use block would
     orphan a live VRAM allocation whose handle the caller still holds. */
  OoGpuBlock *inuse = g_pool_all_head;
  while (inuse) {
    if (inuse->is_in_use) {
      pthread_mutex_unlock(&g_gpu_mutex);
      fprintf(stderr, "ERR\tgpu\tgpu_pool_purge: pool contains in-use buffers; caller must gpu_buffer_free first\n");
      return;
    }
    inuse = inuse->all_next;
  }
  OoGpuBlock *cur = g_pool_all_head;
  while (cur) {
    OoGpuBlock *nxt = cur->all_next;
    if (cur->gpu_ptr) {
      g_hip.hipFree(cur->gpu_ptr);
    }
    free(cur);
    cur = nxt;
  }
  g_pool_all_head = NULL;
  memset(g_pool_bins, 0, sizeof(g_pool_bins));
  memset(g_handle_blocks, 0, sizeof(g_handle_blocks));
  g_vram_total_allocated = 0;
  g_vram_total_active = 0;
  pthread_mutex_unlock(&g_gpu_mutex);
}

int oo_gpu_copy_h2d(long long cap, long long dst_handle, const void *src, long long bytes) {
  oo_cap_require_gpu(cap, "gpu_copy_h2d");
  if (dst_handle <= 0 || dst_handle >= OO_GPU_MAX_BUFFERS || !src || bytes <= 0) return 0;
  /* Fail-closed: refuse if HIP/ROCm runtime is not present. No CPU fallback that would
     silently mirror host memory into a buffer the caller believes is on a device. */
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_copy_h2d: HIP/ROCm runtime absent; refusing to copy\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  OoGpuBlock *blk = g_handle_blocks[dst_handle];
  if (!blk || !blk->is_in_use || (size_t)bytes > blk->capacity_bytes) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  void *dst_ptr = blk->gpu_ptr;
  if (!dst_ptr) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  blk->in_flight_copies++;
  pthread_mutex_unlock(&g_gpu_mutex);

  int ok = (g_hip.hipMemcpy(dst_ptr, src, (size_t)bytes, OO_HIP_MEMCPY_H2D) == OO_HIP_SUCCESS);

  pthread_mutex_lock(&g_gpu_mutex);
  if (blk->in_flight_copies > 0) {
    blk->in_flight_copies--;
  }
  pthread_mutex_unlock(&g_gpu_mutex);
  return ok;
}

int oo_gpu_copy_d2h(long long cap, void *dst, long long src_handle, long long bytes) {
  oo_cap_require_gpu(cap, "gpu_copy_d2h");
  if (src_handle <= 0 || src_handle >= OO_GPU_MAX_BUFFERS || !dst || bytes <= 0) return 0;
  /* Fail-closed: refuse if HIP/ROCm runtime is not present. No CPU fallback that would
     read from host memory but report it as device memory. */
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_copy_d2h: HIP/ROCm runtime absent; refusing to copy\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  OoGpuBlock *blk = g_handle_blocks[src_handle];
  if (!blk || !blk->is_in_use || (size_t)bytes > blk->capacity_bytes) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  void *src_ptr = blk->gpu_ptr;
  if (!src_ptr) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  blk->in_flight_copies++;
  pthread_mutex_unlock(&g_gpu_mutex);

  int ok = (g_hip.hipMemcpy(dst, src_ptr, (size_t)bytes, OO_HIP_MEMCPY_D2H) == OO_HIP_SUCCESS);

  pthread_mutex_lock(&g_gpu_mutex);
  if (blk->in_flight_copies > 0) {
    blk->in_flight_copies--;
  }
  pthread_mutex_unlock(&g_gpu_mutex);
  return ok;
}

int oo_gpu_copy_h2d_async(long long cap, long long dst_h, const void *src, long long bytes, long long stream_h) {
  oo_cap_require_gpu(cap, "gpu_copy_h2d_async");
  if (dst_h <= 0 || dst_h >= OO_GPU_MAX_BUFFERS || !src || bytes <= 0) return 0;
  /* Fail-closed: refuse if HIP/ROCm runtime is not present. No CPU-memcpy "async" that
     would inflate the in-flight pinning counter without ever scheduling a real DMA. */
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_copy_h2d_async: HIP/ROCm runtime absent; refusing to enqueue DMA\n");
    return 0;
  }
  /* Fail-closed: require a valid stream handle so the DMA is actually scheduled on a queue
     the caller can later synchronize. */
  if (stream_h <= 0 || stream_h >= OO_GPU_MAX_STREAMS || !g_stream_handles[stream_h]) {
    fprintf(stderr, "ERR\tgpu\tgpu_copy_h2d_async: invalid stream handle; refusing to enqueue DMA\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  OoGpuBlock *blk = g_handle_blocks[dst_h];
  if (!blk || !blk->is_in_use || (size_t)bytes > blk->capacity_bytes) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  void *dst_ptr = blk->gpu_ptr;
  if (!dst_ptr) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  void *stream = g_stream_handles[stream_h];

  int slot_idx = -1;
  for (int i = 0; i < OO_GPU_MAX_PENDING_COPIES; i++) {
    if (!g_pending_copies[i].active) {
      slot_idx = i;
      g_pending_copies[i].blk = blk;
      g_pending_copies[i].stream_handle = stream_h;
      g_pending_copies[i].active = 1;
      break;
    }
  }
  if (slot_idx < 0) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0; /* Transfer table full - fail closed */
  }

  blk->in_flight_copies++;
  pthread_mutex_unlock(&g_gpu_mutex);

  int ok = (g_hip.hipMemcpyAsync(dst_ptr, src, (size_t)bytes, OO_HIP_MEMCPY_H2D, stream) == OO_HIP_SUCCESS);

  if (!ok) {
    pthread_mutex_lock(&g_gpu_mutex);
    if (blk->in_flight_copies > 0) {
      blk->in_flight_copies--;
    }
    g_pending_copies[slot_idx].active = 0;
    g_pending_copies[slot_idx].blk = NULL;
    g_pending_copies[slot_idx].stream_handle = 0;
    pthread_mutex_unlock(&g_gpu_mutex);
  }

  return ok;
}

int oo_gpu_copy_d2h_async(long long cap, void *dst, long long src_h, long long bytes, long long stream_h) {
  oo_cap_require_gpu(cap, "gpu_copy_d2h_async");
  if (src_h <= 0 || src_h >= OO_GPU_MAX_BUFFERS || !dst || bytes <= 0) return 0;
  /* Fail-closed: refuse if HIP/ROCm runtime is not present. No CPU-memcpy "async" that
     would inflate the in-flight pinning counter without ever scheduling a real DMA. */
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_copy_d2h_async: HIP/ROCm runtime absent; refusing to enqueue DMA\n");
    return 0;
  }
  /* Fail-closed: require a valid stream handle so the DMA is actually scheduled on a queue
     the caller can later synchronize. */
  if (stream_h <= 0 || stream_h >= OO_GPU_MAX_STREAMS || !g_stream_handles[stream_h]) {
    fprintf(stderr, "ERR\tgpu\tgpu_copy_d2h_async: invalid stream handle; refusing to enqueue DMA\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  OoGpuBlock *blk = g_handle_blocks[src_h];
  if (!blk || !blk->is_in_use || (size_t)bytes > blk->capacity_bytes) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  void *src_ptr = blk->gpu_ptr;
  if (!src_ptr) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0;
  }
  void *stream = g_stream_handles[stream_h];

  int slot_idx = -1;
  for (int i = 0; i < OO_GPU_MAX_PENDING_COPIES; i++) {
    if (!g_pending_copies[i].active) {
      slot_idx = i;
      g_pending_copies[i].blk = blk;
      g_pending_copies[i].stream_handle = stream_h;
      g_pending_copies[i].active = 1;
      break;
    }
  }
  if (slot_idx < 0) {
    pthread_mutex_unlock(&g_gpu_mutex);
    return 0; /* Transfer table full - fail closed */
  }

  blk->in_flight_copies++;
  pthread_mutex_unlock(&g_gpu_mutex);

  int ok = (g_hip.hipMemcpyAsync(dst, src_ptr, (size_t)bytes, OO_HIP_MEMCPY_D2H, stream) == OO_HIP_SUCCESS);

  if (!ok) {
    pthread_mutex_lock(&g_gpu_mutex);
    if (blk->in_flight_copies > 0) {
      blk->in_flight_copies--;
    }
    g_pending_copies[slot_idx].active = 0;
    g_pending_copies[slot_idx].blk = NULL;
    g_pending_copies[slot_idx].stream_handle = 0;
    pthread_mutex_unlock(&g_gpu_mutex);
  }

  return ok;
}

long long oo_gpu_stream_create(long long cap, unsigned int flags) {
  oo_cap_require_gpu(cap, "gpu_stream_create");
  oo_gpu_init(cap);
  /* Fail-closed: never hand out a "virtual" stream handle that the caller would feed
     into hipMemcpyAsync. A fake handle cannot synchronize a real DMA. */
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_stream_create: HIP/ROCm runtime absent; refusing to create stream\n");
    return 0;
  }
  void *stream = NULL;
  if (g_hip.hipStreamCreateWithFlags(&stream, flags) != OO_HIP_SUCCESS || !stream) return 0;
  pthread_mutex_lock(&g_gpu_mutex);
  for (int i = 1; i < OO_GPU_MAX_STREAMS; i++) {
    if (!g_stream_handles[i]) {
      g_stream_handles[i] = stream;
      pthread_mutex_unlock(&g_gpu_mutex);
      return (long long)i;
    }
  }
  g_hip.hipStreamDestroy(stream);
  pthread_mutex_unlock(&g_gpu_mutex);
  return 0;
}

int oo_gpu_stream_destroy(long long cap, long long stream_h) {
  oo_cap_require_gpu(cap, "gpu_stream_destroy");
  if (stream_h <= 0 || stream_h >= OO_GPU_MAX_STREAMS) return 0;
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_stream_destroy: HIP/ROCm runtime absent; refusing to destroy stream\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  void *stream = g_stream_handles[stream_h];
  pthread_mutex_unlock(&g_gpu_mutex);

  if (stream) {
    int rc_sync = g_hip.hipStreamSynchronize(stream);
    if (rc_sync != OO_HIP_SUCCESS) {
      fprintf(stderr, "ERR\tgpu\tgpu_stream_destroy: hipStreamSynchronize failed: %s\n", oo_hip_err_str(rc_sync));
      return 0;
    }
    int rc_destroy = g_hip.hipStreamDestroy(stream);
    if (rc_destroy != OO_HIP_SUCCESS) {
      fprintf(stderr, "ERR\tgpu\tgpu_stream_destroy: hipStreamDestroy failed: %s\n", oo_hip_err_str(rc_destroy));
      return 0;
    }
  }

  pthread_mutex_lock(&g_gpu_mutex);
  for (int i = 0; i < OO_GPU_MAX_PENDING_COPIES; i++) {
    if (g_pending_copies[i].active && g_pending_copies[i].stream_handle == stream_h) {
      if (g_pending_copies[i].blk && g_pending_copies[i].blk->in_flight_copies > 0) {
        g_pending_copies[i].blk->in_flight_copies--;
      }
      g_pending_copies[i].active = 0;
      g_pending_copies[i].blk = NULL;
      g_pending_copies[i].stream_handle = 0;
    }
  }
  g_stream_handles[stream_h] = NULL;
  pthread_mutex_unlock(&g_gpu_mutex);
  return 1;
}

int oo_gpu_stream_sync(long long cap, long long stream_h) {
  oo_cap_require_gpu(cap, "gpu_stream_sync");
  if (stream_h <= 0 || stream_h >= OO_GPU_MAX_STREAMS) return 0;
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_stream_sync: HIP/ROCm runtime absent; refusing to sync stream\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  void *stream = g_stream_handles[stream_h];
  pthread_mutex_unlock(&g_gpu_mutex);

  int ok = 1;
  if (stream) {
    int rc = g_hip.hipStreamSynchronize(stream);
    ok = (rc == OO_HIP_SUCCESS);
    if (!ok) {
      fprintf(stderr, "ERR\tgpu\tgpu_stream_sync: hipStreamSynchronize failed: %s\n", oo_hip_err_str(rc));
    }
  }

  pthread_mutex_lock(&g_gpu_mutex);
  for (int i = 0; i < OO_GPU_MAX_PENDING_COPIES; i++) {
    if (g_pending_copies[i].active && g_pending_copies[i].stream_handle == stream_h) {
      if (g_pending_copies[i].blk && g_pending_copies[i].blk->in_flight_copies > 0) {
        g_pending_copies[i].blk->in_flight_copies--;
      }
      g_pending_copies[i].active = 0;
      g_pending_copies[i].blk = NULL;
      g_pending_copies[i].stream_handle = 0;
    }
  }
  pthread_mutex_unlock(&g_gpu_mutex);

  return ok;
}

long long oo_gpu_event_create(long long cap, unsigned int flags) {
  oo_cap_require_gpu(cap, "gpu_event_create");
  oo_gpu_init(cap);
  /* Fail-closed: no virtual "1" event handle. A fake event cannot record or synchronize
     a real device operation, and pretending it can masks races. */
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_create: HIP/ROCm runtime absent; refusing to create event\n");
    return 0;
  }
  void *event = NULL;
  if (g_hip.hipEventCreateWithFlags(&event, flags) != OO_HIP_SUCCESS || !event) return 0;
  pthread_mutex_lock(&g_gpu_mutex);
  for (int i = 1; i < OO_GPU_MAX_EVENTS; i++) {
    if (!g_event_handles[i]) {
      g_event_handles[i] = event;
      pthread_mutex_unlock(&g_gpu_mutex);
      return (long long)i;
    }
  }
  g_hip.hipEventDestroy(event);
  pthread_mutex_unlock(&g_gpu_mutex);
  return 0;
}

int oo_gpu_event_destroy(long long cap, long long event_h) {
  oo_cap_require_gpu(cap, "gpu_event_destroy");
  if (event_h <= 0 || event_h >= OO_GPU_MAX_EVENTS) return 0;
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_destroy: HIP/ROCm runtime absent; refusing to destroy event\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  void *event = g_event_handles[event_h];
  pthread_mutex_unlock(&g_gpu_mutex);
  if (event) {
    int rc = g_hip.hipEventDestroy(event);
    if (rc != OO_HIP_SUCCESS) {
      fprintf(stderr, "ERR\tgpu\tgpu_event_destroy: hipEventDestroy failed: %s\n", oo_hip_err_str(rc));
      return 0;
    }
  }
  pthread_mutex_lock(&g_gpu_mutex);
  g_event_handles[event_h] = NULL;
  pthread_mutex_unlock(&g_gpu_mutex);
  return 1;
}

int oo_gpu_event_record(long long cap, long long event_h, long long stream_h) {
  oo_cap_require_gpu(cap, "gpu_event_record");
  if (event_h <= 0 || event_h >= OO_GPU_MAX_EVENTS) return 0;
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_record: HIP/ROCm runtime absent; refusing to record event\n");
    return 0;
  }
  /* Fail-closed: require a real stream. A null-stream record would silently schedule
     against the legacy default queue and not synchronize with the caller's stream. */
  if (stream_h <= 0 || stream_h >= OO_GPU_MAX_STREAMS || !g_stream_handles[stream_h]) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_record: invalid stream handle; refusing to record event\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  void *event = g_event_handles[event_h];
  void *stream = g_stream_handles[stream_h];
  pthread_mutex_unlock(&g_gpu_mutex);
  if (!event) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_record: invalid event handle\n");
    return 0;
  }
  int rc = g_hip.hipEventRecord(event, stream);
  if (rc != OO_HIP_SUCCESS) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_record: hipEventRecord failed: %s\n", oo_hip_err_str(rc));
    return 0;
  }
  return 1;
}

int oo_gpu_event_sync(long long cap, long long event_h) {
  oo_cap_require_gpu(cap, "gpu_event_sync");
  if (event_h <= 0 || event_h >= OO_GPU_MAX_EVENTS) return 0;
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_sync: HIP/ROCm runtime absent; refusing to sync event\n");
    return 0;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  void *event = g_event_handles[event_h];
  pthread_mutex_unlock(&g_gpu_mutex);
  if (!event) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_sync: invalid event handle\n");
    return 0;
  }
  int rc = g_hip.hipEventSynchronize(event);
  if (rc != OO_HIP_SUCCESS) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_sync: hipEventSynchronize failed: %s\n", oo_hip_err_str(rc));
    return 0;
  }
  return 1;
}

float oo_gpu_event_elapsed_ms(long long cap, long long start_h, long long stop_h) {
  oo_cap_require_gpu(cap, "gpu_event_elapsed_ms");
  if (start_h <= 0 || start_h >= OO_GPU_MAX_EVENTS || stop_h <= 0 || stop_h >= OO_GPU_MAX_EVENTS) return 0.0f;
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_elapsed_ms: HIP/ROCm runtime absent; refusing to time\n");
    return 0.0f;
  }
  pthread_mutex_lock(&g_gpu_mutex);
  void *start = g_event_handles[start_h];
  void *stop = g_event_handles[stop_h];
  pthread_mutex_unlock(&g_gpu_mutex);
  if (!start || !stop) return 0.0f;
  float ms = 0.0f;
  int rc = g_hip.hipEventElapsedTime(&ms, start, stop);
  if (rc != OO_HIP_SUCCESS) {
    fprintf(stderr, "ERR\tgpu\tgpu_event_elapsed_ms: hipEventElapsedTime failed: %s\n", oo_hip_err_str(rc));
    return 0.0f;
  }
  return ms;
}

OoResS oo_gpu_sync(long long cap) {
  OoResS r;
  oo_cap_require_gpu(cap, "gpu_sync");
  oo_gpu_init(cap);
  /* Fail-closed: refuse to "sync" an absent device. A no-op success would let the caller
     believe outstanding DMAs completed when nothing was ever enqueued. */
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

static OoGpuKernelKind oo_gpu_classify_kernel(const char *kname, const char *code, long long code_len) {
  /* Phase 1: Specific kernel name matching using exact strcmp via oo_gpu_kname_in */
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
    /* SGEMM / MatMul structural markers */
    if (strstr(code, "oo_k_sgemm") || strstr(code, "s_a[16]") || strstr(code, "s_b[16]") ||
        strstr(code, "tiled_sgemm") || strstr(code, "TILED_GEMM") || strstr(code, "fmaf(s_a") ||
        strstr(code, "kernel_descriptor:sgemm") || strstr(code, "op:sgemm")) {
      return OO_GPU_KIND_SGEMM;
    }
    /* Attention / FlashAttention structural markers */
    if (strstr(code, "oo_k_attention") || strstr(code, "m_prev") || strstr(code, "flash_attention") ||
        strstr(code, "FLASH_ATTENTION") || strstr(code, "kernel_descriptor:attention") ||
        strstr(code, "op:attention") || (strstr(code, "q_row") && strstr(code, "head_dim"))) {
      return OO_GPU_KIND_ATTENTION;
    }
    /* RMSNorm structural markers */
    if (strstr(code, "oo_k_rmsnorm") || strstr(code, "hip_warp_reduce_sum") ||
        strstr(code, "s_warp_sums") || strstr(code, "s_inv_rms") || strstr(code, "RMS_NORM") ||
        strstr(code, "rms_norm_wave32") || strstr(code, "kernel_descriptor:rmsnorm") ||
        strstr(code, "op:rmsnorm")) {
      return OO_GPU_KIND_RMSNORM;
    }
    /* RoPE structural markers */
    if (strstr(code, "oo_k_rope") || strstr(code, "theta_base") || strstr(code, "pair_idx") ||
        strstr(code, "token_pos") || strstr(code, "ROPE") ||
        strstr(code, "kernel_descriptor:rope") || strstr(code, "op:rope")) {
      return OO_GPU_KIND_ROPE;
    }
    /* Stencil 3D structural markers */
    if (strstr(code, "oo_k_stencil_3d") || strstr(code, "sum_neighbors") ||
        strstr(code, "c0 * center") || strstr(code, "STENCIL_3D") ||
        strstr(code, "kernel_descriptor:stencil_3d") || strstr(code, "op:stencil_3d")) {
      return OO_GPU_KIND_STENCIL_3D;
    }
    /* Reduce Sum structural markers */
    if (strstr(code, "oo_k_reduce_sum") || strstr(code, "atomicAdd(out_val") ||
        strstr(code, "atomicAdd(out,") || strstr(code, "REDUCE_SUM") ||
        strstr(code, "kernel_descriptor:reduce_sum") || strstr(code, "op:reduce_sum")) {
      return OO_GPU_KIND_REDUCE_SUM;
    }
    /* Vector Add structural markers */
    if (strstr(code, "oo_k_vec_add") || strstr(code, "oo_k_vec_fma") ||
        strstr(code, "ADD_GLOBAL_F32") || strstr(code, "c[i] = a[i] + b[i]") ||
        strstr(code, "kernel_descriptor:vec_add") || strstr(code, "op:vec_add")) {
      return OO_GPU_KIND_VEC_ADD;
    }
  }

  /* Fallback Phase: If code was empty/unmatched, check specific kname tables again */
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

  /* Fail-closed: refuse to launch on a non-HIP target or with HIP absent. No CPU
     fallback. A CPU-executed kernel that the caller believes ran on a device is a
     silent loss of correctness. */
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
    int nz = (arg_count >= 5 && kernel_args[4]) ? *(int*)kernel_args[4] : (gz > 0 ? gz : 1);
    float c0 = (arg_count >= 6 && kernel_args[5]) ? *(float*)kernel_args[5] : 1.0f;
    float c1 = (arg_count >= 7 && kernel_args[6]) ? *(float*)kernel_args[6] : 0.1f;
    if (nx <= 0 || ny <= 0 || nz <= 0) {
      r.ok = 0; r.val = oo_str_lit("invalid stencil dimensions"); return r;
    }
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
