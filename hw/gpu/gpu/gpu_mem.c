/* gpu/gpu_mem.c — host↔device memory copies: synchronous (h2d/d2h) and
 * asynchronous (h2d_async/d2h_async). The async paths claim a slot in
 * g_pending_copies (defined in gpu/gpu.c) so the owning stream's
 * gpu_stream_sync / gpu_stream_destroy can release the in-flight pin.
 * Cap token: GpuCap via oo_cap_require_gpu. */
#include "../gpu.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#define OO_GPU_MAX_PENDING_COPIES 1024

extern OoGpuBlock *g_handle_blocks[OO_GPU_MAX_BUFFERS];
extern OoGpuPendingCopy g_pending_copies[OO_GPU_MAX_PENDING_COPIES];
extern void *g_stream_handles[OO_GPU_MAX_STREAMS];
extern pthread_mutex_t g_gpu_mutex;
extern OoHipApi g_hip;
extern int g_hip_ok;

int oo_gpu_copy_h2d(long long cap, long long dst_handle, const void *src, long long bytes) {
  oo_cap_require_gpu(cap, "gpu_copy_h2d");
  if (dst_handle <= 0 || dst_handle >= OO_GPU_MAX_BUFFERS || !src || bytes <= 0) return 0;
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
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_copy_h2d_async: HIP/ROCm runtime absent; refusing to enqueue DMA\n");
    return 0;
  }
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
    return 0;
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
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_copy_d2h_async: HIP/ROCm runtime absent; refusing to enqueue DMA\n");
    return 0;
  }
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
    return 0;
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
