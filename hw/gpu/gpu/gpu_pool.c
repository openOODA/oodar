/* gpu/gpu_pool.c — segregated-size VRAM pool: alloc, free, get_ptr,
 * get_size, and purge. The pool is global; every public entry point
 * takes g_gpu_mutex (defined in gpu/gpu.c). Pool state (g_pool_bins,
 * g_pool_all_head, g_handle_blocks, g_vram_total_*) is also defined
 * in gpu/gpu.c and accessed via extern.
 * Cap token: GpuCap via oo_cap_require_gpu. */
#include "../gpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

extern OoGpuBlock *g_pool_bins[OO_GPU_POOL_BINS];
extern OoGpuBlock *g_pool_all_head;
extern OoGpuBlock *g_handle_blocks[OO_GPU_MAX_BUFFERS];
extern size_t g_vram_total_allocated;
extern size_t g_vram_total_active;
extern pthread_mutex_t g_gpu_mutex;
extern OoHipApi g_hip;
extern int g_hip_ok;
const char* oo_hip_err_str(int rc);
int oo_gpu_size_to_bin(size_t bytes);
size_t oo_gpu_bin_to_size(int bin);

long long oo_gpu_buffer_alloc(long long cap, long long bytes, int unified) {
  (void)unified;
  oo_cap_require_gpu(cap, "gpu_buffer_alloc");
  if (bytes <= 0 || bytes > OO_ALLOC_BYTES_MAX) return 0;
  oo_gpu_init(cap);
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
    if (!blk->gpu_ptr) {
      void *ptr = NULL;
      int rc = g_hip.hipMalloc(&ptr, alloc_sz);
      if (rc != OO_HIP_SUCCESS || !ptr) {
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
  if (!g_hip_ok) {
    fprintf(stderr, "ERR\tgpu\tgpu_pool_purge: HIP/ROCm runtime absent; refusing to purge\n");
    return;
  }
  if (g_hip.hipDeviceSynchronize) {
    int rc = g_hip.hipDeviceSynchronize();
    if (rc != OO_HIP_SUCCESS) {
      fprintf(stderr, "ERR\tgpu\tgpu_pool_purge: hipDeviceSynchronize failed: %s\n", oo_hip_err_str(rc));
      return;
    }
  }
  pthread_mutex_lock(&g_gpu_mutex);
  for (int i = 0; i < 1024; i++) {
    if (g_pending_copies[i].active) {
      if (g_pending_copies[i].blk && g_pending_copies[i].blk->in_flight_copies > 0) {
        g_pending_copies[i].blk->in_flight_copies--;
      }
      g_pending_copies[i].active = 0;
      g_pending_copies[i].blk = NULL;
      g_pending_copies[i].stream_handle = 0;
    }
  }
  OoGpuBlock *chk = g_pool_all_head;
  while (chk) {
    if (chk->in_flight_copies > 0) {
      pthread_mutex_unlock(&g_gpu_mutex);
      fprintf(stderr, "ERR\tgpu\tgpu_pool_purge: in-flight copies remain after sync; refusing to purge\n");
      return;
    }
    chk = chk->all_next;
  }
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
