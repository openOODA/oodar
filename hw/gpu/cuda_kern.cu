/* hw/gpu/cuda_kern.cu — liboo_cuda.so compute kernels (NVIDIA twin of hip_kern.hip).
 * Build (out-of-band, needs nvcc + NVIDIA GPU; mirrors the HIP flow):
 *   nvcc -shared -fPIC -O2 -arch=sm_89 -o liboo_cuda.so hw/gpu/cuda_kern.cu
 * oodar dlopens it via OODA_CUDA_LIB / ./liboo_cuda.so (gpu_cuda_dlopen.c).
 * Each launcher does H2D, one kernel, D2H, then CPU-verifies (rc 5 on
 * numerical mismatch). Naive kernels: correctness first, perf second. */
#include <cuda_runtime.h>
#include <math.h>
#include <stddef.h>

__global__ void oo_k_cuda_vec_add(const float *a, const float *b, float *c, int n) {
  int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < n) c[i] = a[i] + b[i];
}

__global__ void oo_k_cuda_sgemm(const float *a, const float *b, float *c, int m, int n, int k) {
  int r = blockIdx.y * blockDim.y + threadIdx.y;
  int col = blockIdx.x * blockDim.x + threadIdx.x;
  if (r >= m || col >= n) return;
  float acc = 0.0f;
  for (int t = 0; t < k; t++) acc += a[r * k + t] * b[t * n + col];
  c[r * n + col] = acc;
}

/* One thread per row; loops dim (correct for any dim, no shared-mem cap). */
__global__ void oo_k_cuda_rmsnorm(const float *x, const float *g, float *o, int rows, int dim) {
  int r = blockIdx.x * blockDim.x + threadIdx.x;
  if (r >= rows) return;
  float ss = 0.0f;
  for (int d = 0; d < dim; d++) { float v = x[r * dim + d]; ss += v * v; }
  float inv = 1.0f / sqrtf(ss / (float)dim + 1e-6f);
  for (int d = 0; d < dim; d++) o[r * dim + d] = x[r * dim + d] * inv * (g ? g[d] : 1.0f);
}

/* Single-head scaled dot-product attention, one thread per query pos. */
__global__ void oo_k_cuda_attn(const float *q, const float *k, const float *v, float *o, int s, int d) {
  int p = blockIdx.x * blockDim.x + threadIdx.x;
  if (p >= s) return;
  float inv = 1.0f / sqrtf((float)d);
  float mx = -1e30f;
  for (int t = 0; t < s; t++) {
    float dot = 0.0f;
    for (int h = 0; h < d; h++) dot += q[p * d + h] * k[t * d + h];
    dot *= inv;
    if (dot > mx) mx = dot;
  }
  float denom = 0.0f;
  for (int t = 0; t < s; t++) {
    float dot = 0.0f;
    for (int h = 0; h < d; h++) dot += q[p * d + h] * k[t * d + h];
    denom += expf(dot * inv - mx);
  }
  for (int h = 0; h < d; h++) {
    float acc = 0.0f;
    for (int t = 0; t < s; t++) {
      float dot = 0.0f;
      for (int j = 0; j < d; j++) dot += q[p * d + j] * k[t * d + j];
      acc += expf(dot * inv - mx) / denom * v[t * d + h];
    }
    o[p * d + h] = acc;
  }
}

/* Grid-stride sum into one block, then shared-mem tree reduction. */
__global__ void oo_k_cuda_reduce(const float *in, float *partial, int n) {
  __shared__ float sh[256];
  int tid = threadIdx.x;
  float acc = 0.0f;
  for (int i = blockIdx.x * blockDim.x + tid; i < n; i += gridDim.x * blockDim.x) acc += in[i];
  sh[tid] = acc;
  __syncthreads();
  for (int s = blockDim.x / 2; s > 0; s >>= 1) {
    if (tid < s) sh[tid] += sh[tid + s];
    __syncthreads();
  }
  if (tid == 0) partial[blockIdx.x] = sh[0];
}

#define OO_CU_CHK(call) do { if ((call) != cudaSuccess) goto fail; } while (0)

extern "C" {

int oo_cuda_vec_add_launch(const float *ha, const float *hb, float *hc, int n) {
  float *da = 0, *db = 0, *dc = 0;
  size_t bytes;
  if (!ha || !hb || !hc || n <= 0) return 1;
  bytes = (size_t)n * sizeof(float);
  if (cudaMalloc((void **)&da, bytes) != cudaSuccess) return 2;
  if (cudaMalloc((void **)&db, bytes) != cudaSuccess) { cudaFree(da); return 2; }
  if (cudaMalloc((void **)&dc, bytes) != cudaSuccess) { cudaFree(da); cudaFree(db); return 2; }
  OO_CU_CHK(cudaMemcpy(da, ha, bytes, cudaMemcpyHostToDevice));
  OO_CU_CHK(cudaMemcpy(db, hb, bytes, cudaMemcpyHostToDevice));
  oo_k_cuda_vec_add<<<(n + 255) / 256, 256>>>(da, db, dc, n);
  OO_CU_CHK(cudaGetLastError());
  OO_CU_CHK(cudaDeviceSynchronize());
  OO_CU_CHK(cudaMemcpy(hc, dc, bytes, cudaMemcpyDeviceToHost));
  cudaFree(da); cudaFree(db); cudaFree(dc);
  for (int i = 0; i < n; i++)
    if (fabsf(hc[i] - (ha[i] + hb[i])) > 1e-5f) return 5;
  return 0;
fail:
  cudaFree(da); cudaFree(db); cudaFree(dc);
  return 3;
}

int oo_cuda_sgemm_launch(const float *ha, const float *hb, float *hc, int m, int n, int k) {
  float *da = 0, *db = 0, *dc = 0;
  dim3 blk(16, 16), grd((n + 15) / 16, (m + 15) / 16);
  if (!ha || !hb || !hc || m <= 0 || n <= 0 || k <= 0) return 1;
  if (cudaMalloc((void **)&da, (size_t)m * k * 4) != cudaSuccess) return 2;
  if (cudaMalloc((void **)&db, (size_t)k * n * 4) != cudaSuccess) { cudaFree(da); return 2; }
  if (cudaMalloc((void **)&dc, (size_t)m * n * 4) != cudaSuccess) { cudaFree(da); cudaFree(db); return 2; }
  OO_CU_CHK(cudaMemcpy(da, ha, (size_t)m * k * 4, cudaMemcpyHostToDevice));
  OO_CU_CHK(cudaMemcpy(db, hb, (size_t)k * n * 4, cudaMemcpyHostToDevice));
  oo_k_cuda_sgemm<<<grd, blk>>>(da, db, dc, m, n, k);
  OO_CU_CHK(cudaGetLastError());
  OO_CU_CHK(cudaDeviceSynchronize());
  OO_CU_CHK(cudaMemcpy(hc, dc, (size_t)m * n * 4, cudaMemcpyDeviceToHost));
  cudaFree(da); cudaFree(db); cudaFree(dc);
  for (int r = 0; r < m; r++) for (int c = 0; c < n; c++) {
    float e = 0.0f;
    for (int t = 0; t < k; t++) e += ha[r * k + t] * hb[t * n + c];
    if (fabsf(hc[r * n + c] - e) > 1e-3f) return 5;
  }
  return 0;
fail:
  cudaFree(da); cudaFree(db); cudaFree(dc);
  return 3;
}

int oo_cuda_rmsnorm_launch(const float *hx, const float *hg, float *ho, int rows, int dim) {
  float *dx = 0, *dg = 0, *do_ = 0;
  if (!hx || !ho || rows <= 0 || dim <= 0) return 1;
  if (cudaMalloc((void **)&dx, (size_t)rows * dim * 4) != cudaSuccess) return 2;
  if (cudaMalloc((void **)&dg, (size_t)dim * 4) != cudaSuccess) { cudaFree(dx); return 2; }
  if (cudaMalloc((void **)&do_, (size_t)rows * dim * 4) != cudaSuccess) { cudaFree(dx); cudaFree(dg); return 2; }
  OO_CU_CHK(cudaMemcpy(dx, hx, (size_t)rows * dim * 4, cudaMemcpyHostToDevice));
  if (hg) OO_CU_CHK(cudaMemcpy(dg, hg, (size_t)dim * 4, cudaMemcpyHostToDevice));
  oo_k_cuda_rmsnorm<<<(rows + 255) / 256, 256>>>(dx, hg ? dg : 0, do_, rows, dim);
  OO_CU_CHK(cudaGetLastError());
  OO_CU_CHK(cudaDeviceSynchronize());
  OO_CU_CHK(cudaMemcpy(ho, do_, (size_t)rows * dim * 4, cudaMemcpyDeviceToHost));
  cudaFree(dx); cudaFree(dg); cudaFree(do_);
  for (int r = 0; r < rows; r++) {
    float ss = 0.0f;
    for (int d = 0; d < dim; d++) ss += hx[r * dim + d] * hx[r * dim + d];
    float inv = 1.0f / sqrtf(ss / (float)dim + 1e-6f);
    for (int d = 0; d < dim; d++) {
      float e = hx[r * dim + d] * inv * (hg ? hg[d] : 1.0f);
      if (fabsf(ho[r * dim + d] - e) > 1e-3f) return 5;
    }
  }
  return 0;
fail:
  cudaFree(dx); cudaFree(dg); cudaFree(do_);
  return 3;
}

int oo_cuda_attention_launch(const float *hq, const float *hk, const float *hv, float *ho, int s, int d) {
  float *dq = 0, *dk = 0, *dv = 0, *do_ = 0;
  size_t qkb = (size_t)s * d * 4;
  float inv = 0.0f;
  if (!hq || !hk || !hv || !ho || s <= 0 || d <= 0) return 1;
  if (cudaMalloc((void **)&dq, qkb) != cudaSuccess) return 2;
  if (cudaMalloc((void **)&dk, qkb) != cudaSuccess) { cudaFree(dq); return 2; }
  if (cudaMalloc((void **)&dv, qkb) != cudaSuccess) { cudaFree(dq); cudaFree(dk); return 2; }
  if (cudaMalloc((void **)&do_, qkb) != cudaSuccess) { cudaFree(dq); cudaFree(dk); cudaFree(dv); return 2; }
  OO_CU_CHK(cudaMemcpy(dq, hq, qkb, cudaMemcpyHostToDevice));
  OO_CU_CHK(cudaMemcpy(dk, hk, qkb, cudaMemcpyHostToDevice));
  OO_CU_CHK(cudaMemcpy(dv, hv, qkb, cudaMemcpyHostToDevice));
  oo_k_cuda_attn<<<(s + 255) / 256, 256>>>(dq, dk, dv, do_, s, d);
  OO_CU_CHK(cudaGetLastError());
  OO_CU_CHK(cudaDeviceSynchronize());
  OO_CU_CHK(cudaMemcpy(ho, do_, qkb, cudaMemcpyDeviceToHost));
  cudaFree(dq); cudaFree(dk); cudaFree(dv); cudaFree(do_);
  inv = 1.0f / sqrtf((float)d);
  for (int p = 0; p < s; p++) {
    float mx = -1e30f, den = 0.0f;
    for (int t = 0; t < s; t++) {
      float dot = 0.0f;
      for (int h = 0; h < d; h++) dot += hq[p * d + h] * hk[t * d + h];
      dot *= inv;
      if (dot > mx) mx = dot;
    }
    for (int t = 0; t < s; t++) {
      float dot = 0.0f;
      for (int h = 0; h < d; h++) dot += hq[p * d + h] * hk[t * d + h];
      den += expf(dot * inv - mx);
    }
    for (int h = 0; h < d; h++) {
      float acc = 0.0f;
      for (int t = 0; t < s; t++) {
        float dot = 0.0f;
        for (int j = 0; j < d; j++) dot += hq[p * d + j] * hk[t * d + j];
        acc += expf(dot * inv - mx) / den * hv[t * d + h];
      }
      if (fabsf(ho[p * d + h] - acc) > 1e-3f) return 5;
    }
  }
  return 0;
fail:
  cudaFree(dq); cudaFree(dk); cudaFree(dv); cudaFree(do_);
  return 3;
}

int oo_cuda_reduce_sum_launch(const float *hin, float *hout, int n) {
  float *din = 0, *dpar = 0, hpar[64];
  int blocks;
  float total;
  double e = 0.0;
  if (!hin || !hout || n <= 0) return 1;
  blocks = (n + 255) / 256;
  if (blocks > 64) blocks = 64;
  if (cudaMalloc((void **)&din, (size_t)n * 4) != cudaSuccess) return 2;
  if (cudaMalloc((void **)&dpar, 64 * 4) != cudaSuccess) { cudaFree(din); return 2; }
  OO_CU_CHK(cudaMemcpy(din, hin, (size_t)n * 4, cudaMemcpyHostToDevice));
  oo_k_cuda_reduce<<<blocks, 256>>>(din, dpar, n);
  OO_CU_CHK(cudaGetLastError());
  OO_CU_CHK(cudaDeviceSynchronize());
  OO_CU_CHK(cudaMemcpy(hpar, dpar, (size_t)blocks * 4, cudaMemcpyDeviceToHost));
  cudaFree(din); cudaFree(dpar);
  total = 0.0f;
  for (int b = 0; b < blocks; b++) total += hpar[b];
  hout[0] = total;
  /* Double-precision CPU reference: float serial sum saturates past 2^24
   * (adding 1.0f to 16777216.0f is a no-op), so float-vs-float would
   * flag the GPU's MORE accurate tree sum as a mismatch on large n. */
  e = 0.0;
  for (int i = 0; i < n; i++) e += (double)hin[i];
  if (fabs((double)total - e) > 1e-4 * (1.0 + fabs(e))) return 5;
  return 0;
fail:
  cudaFree(din); cudaFree(dpar);
  return 3;
}

} /* extern "C" */
