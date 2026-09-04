#ifndef CHS_RT_GPU_H
#define CHS_RT_GPU_H

#include "chs_rt.h"
#include "chs_rt_caps.h"
#include "chs_rt_types.h"
#include <stddef.h>

#define OO_GPU_MAX_BUFFERS 1024
#define OO_GPU_MAX_STREAMS 64
#define OO_GPU_MAX_EVENTS 64

#define OO_HIP_SUCCESS 0
#define OO_HIP_MEMCPY_H2D 1
#define OO_HIP_MEMCPY_D2H 2
#define OO_HIP_MEMCPY_D2D 3

typedef struct {
  void *device_handle;
  void *context_handle;
  int backend_type; /* 0=None/CPU, 1=CUDA, 2=Vulkan, 3=Metal, 4=HIP/ROCm */
  char device_name[128];
  char arch_name[64];
  int warp_size;
  int compute_units;
  unsigned long long total_vram_bytes;
  unsigned long long free_vram_bytes;
} OoGpuDevice;

typedef struct {
  void *gpu_ptr;
  void *host_ptr;
  unsigned long long size_bytes;
  int is_unified_memory;
  int is_pooled;
} OoGpuBuffer;

/* Lifecycle & Device Discovery */
int oo_gpu_init(long long cap);
int oo_gpu_hip_available(void);
OoResS oo_gpu_probe_device(long long cap, int device_id);

/* Segregated VRAM Memory Pool & Buffer Management */
long long oo_gpu_buffer_alloc(long long cap, long long bytes, int unified);
int oo_gpu_buffer_free(long long cap, long long buf_handle);
void* oo_gpu_buffer_get_ptr(long long cap, long long buf_handle);
size_t oo_gpu_buffer_get_size(long long cap, long long buf_handle);
void oo_gpu_pool_purge(long long cap);

/* Memory Transfers */
int oo_gpu_copy_h2d(long long cap, long long dst_handle, const void *src, long long bytes);
int oo_gpu_copy_d2h(long long cap, void *dst, long long src_handle, long long bytes);
int oo_gpu_copy_h2d_async(long long cap, long long dst_handle, const void *src, long long bytes, long long stream_handle);
int oo_gpu_copy_d2h_async(long long cap, void *dst, long long src_handle, long long bytes, long long stream_handle);

/* Asynchronous Streams & Events */
long long oo_gpu_stream_create(long long cap, unsigned int flags);
int oo_gpu_stream_destroy(long long cap, long long stream_handle);
int oo_gpu_stream_sync(long long cap, long long stream_handle);
long long oo_gpu_event_create(long long cap, unsigned int flags);
int oo_gpu_event_destroy(long long cap, long long event_handle);
int oo_gpu_event_record(long long cap, long long event_handle, long long stream_handle);
int oo_gpu_event_sync(long long cap, long long event_handle);
float oo_gpu_event_elapsed_ms(long long cap, long long start_handle, long long stop_handle);

/* Global Execution & Synchronization */
OoResS oo_gpu_sync(long long cap);
OoResS oo_gpu_launch(long long cap, OoStr shader);
OoResS oo_gpu_launch_kernel(long long cap, OoStr target, OoStr kernel_name, OoStr code,
                            int gx, int gy, int gz, int bx, int by, int bz,
                            void **kernel_args, int arg_count);

/* Dynamic ROCm / HIP Kernel Dispatch Functions */
OoResS oo_gpu_hip_vec_add(long long cap, float *a, float *b, float *c, int n);
OoResS oo_gpu_hip_sgemm(long long cap, const float *a, const float *b, float *c, int m, int n, int k);
OoResS oo_gpu_hip_rmsnorm(long long cap, const float *x, const float *gamma, float *out, int rows, int dim);
OoResS oo_gpu_hip_attention(long long cap, const float *q, const float *k, const float *v, float *out, int seq_len, int d_head);
OoResS oo_gpu_hip_reduce_sum(long long cap, const float *in, float *out, int n);
OoResS oo_gpu_hip_rope(long long cap, const float *in, const float *cos_val, const float *sin_val, float *out, int seq_len, int dim);
OoResS oo_gpu_hip_stencil_3d(long long cap, const float *in, float *out, int nx, int ny, int nz, float c0, float c1);
OoResS oo_gpu_hip_try_launch(long long cap, OoStr shader);

#endif /* CHS_RT_GPU_H */
