/* gpu/gpu_stream.c — stream + event lifecycle: create, destroy, sync,
 * record, elapsed-time. Each stream owns its in-flight pending-copies
 * (tracked in g_pending_copies, defined in gpu/gpu.c) — when the stream
 * is destroyed or synced, those slots are released and the in-flight
 * pin counters on the underlying buffers are decremented.
 * Cap token: GpuCap via oo_cap_require_gpu. */
#include "../gpu.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

extern void *g_stream_handles[OO_GPU_MAX_STREAMS];
extern void *g_event_handles[OO_GPU_MAX_EVENTS];
extern OoGpuPendingCopy g_pending_copies[OO_GPU_MAX_PENDING_COPIES];
extern pthread_mutex_t g_gpu_mutex;
extern OoHipApi g_hip;
extern int g_hip_ok;
const char* oo_hip_err_str(int rc);

long long oo_gpu_stream_create(long long cap, unsigned int flags) {
  oo_cap_require_gpu(cap, "gpu_stream_create");
  oo_gpu_init(cap);
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
  for (int i = 0; i < 1024; i++) {
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
  for (int i = 0; i < 1024; i++) {
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
