// AMD HIP/ROCm RDNA3/CDNA compute kernel suite. Compiled via hipcc.
#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <assert.h>

#define WAVE_SIZE 32
#define TILE_DIM 16

/* 1. Core Foundation: Vector 128-bit Addition & FMA */
__global__ void oo_k_vec_add(const float* a, const float* b, float* c, int n) {
    int i = (int)(blockIdx.x * blockDim.x + threadIdx.x);
    if (i < n) {
        c[i] = a[i] + b[i];
    }
}

__global__ void oo_k_vec_fma_f4(const float4* a, const float4* b, const float4* c, float4* out, int n4) {
    int i = (int)(blockIdx.x * blockDim.x + threadIdx.x);
    if (i < n4) {
        float4 va = a[i];
        float4 vb = b[i];
        float4 vc = c[i];
        float4 res;
        res.x = va.x * vb.x + vc.x;
        res.y = va.y * vb.y + vc.y;
        res.z = va.z * vb.z + vc.z;
        res.w = va.w * vb.w + vc.w;
        out[i] = res;
    }
}

/* 2. Linear Algebra: 2D Tiled SGEMM with LDS Caching */
__global__ void oo_k_sgemm_tiled(const float* A, const float* B, float* C, int M, int N, int K) {
    __shared__ float sA[TILE_DIM][TILE_DIM];
    __shared__ float sB[TILE_DIM][TILE_DIM];

    int bx = blockIdx.x, by = blockIdx.y;
    int tx = threadIdx.x, ty = threadIdx.y;

    int row = by * TILE_DIM + ty;
    int col = bx * TILE_DIM + tx;

    float acc = 0.0f;
    int num_tiles = (K + TILE_DIM - 1) / TILE_DIM;

    for (int t = 0; t < num_tiles; ++t) {
        int a_col = t * TILE_DIM + tx;
        int b_row = t * TILE_DIM + ty;

        sA[ty][tx] = (row < M && a_col < K) ? A[row * K + a_col] : 0.0f;
        sB[ty][tx] = (b_row < K && col < N) ? B[b_row * N + col] : 0.0f;
        __syncthreads();

        #pragma unroll
        for (int k = 0; k < TILE_DIM; ++k) {
            acc += sA[ty][k] * sB[k][tx];
        }
        __syncthreads();
    }

    if (row < M && col < N) {
        C[row * N + col] = acc;
    }
}

/* 3. AI Acceleration: RMSNorm with Wave32 Warp Shuffle */
__inline__ __device__ float wave32_sum(float val) {
    val += __shfl_down(val, 16, 32);
    val += __shfl_down(val, 8, 32);
    val += __shfl_down(val, 4, 32);
    val += __shfl_down(val, 2, 32);
    val += __shfl_down(val, 1, 32);
    return val;
}

__global__ void oo_k_rmsnorm(const float* x, const float* gamma, float* out, int rows, int dim) {
    int row = blockIdx.x;
    if (row >= rows) return;
    int tid = threadIdx.x;

    const float* row_x = x + (size_t)row * dim;
    float* row_out = out + (size_t)row * dim;

    float sum_sq = 0.0f;
    for (int i = tid; i < dim; i += blockDim.x) {
        float v = row_x[i];
        sum_sq += v * v;
    }

    __shared__ float s_warp_sums[32];
    int lane = tid % 32;
    int warp_id = tid / 32;
    float warp_val = wave32_sum(sum_sq);
    if (lane == 0) s_warp_sums[warp_id] = warp_val;
    __syncthreads();

    int num_warps = (blockDim.x + 31) / 32;
    __shared__ float s_inv_rms;
    if (tid < 32) {
        float v = (tid < num_warps) ? s_warp_sums[tid] : 0.0f;
        float block_sum = wave32_sum(v);
        if (tid == 0) {
            s_inv_rms = rsqrtf(block_sum / (float)dim + 1e-5f);
        }
    }
    __syncthreads();

    float inv_rms = s_inv_rms;
    for (int i = tid; i < dim; i += blockDim.x) {
        row_out[i] = row_x[i] * inv_rms * (gamma ? gamma[i] : 1.0f);
    }
}

/* 4. AI Acceleration: Fused Attention (Online Softmax) */
__global__ void oo_k_attention(const float* q, const float* k, const float* v, float* out, int seq_len, int d_head) {
    assert(d_head > 0 && d_head <= 256);
    if (d_head <= 0 || d_head > 256) return;
    int row = blockIdx.x;
    if (row >= seq_len) return;
    int tid = threadIdx.x;

    float scale = 1.0f / sqrtf((float)d_head);
    const float* q_row = q + (size_t)row * d_head;

    float m_prev = -1e30f;
    float l_prev = 0.0f;
    float acc = 0.0f;

    for (int s = 0; s < seq_len; ++s) {
        float dot = 0.0f;
        const float* k_s = k + (size_t)s * d_head;
        for (int d = 0; d < d_head; ++d) {
            dot += q_row[d] * k_s[d];
        }
        dot *= scale;

        float m_new = dot > m_prev ? dot : m_prev;
        float e = expf(dot - m_new);
        float alpha = (m_prev == -1e30f) ? 0.0f : expf(m_prev - m_new);
        float l_new = alpha * l_prev + e;

        float v_val = (tid < d_head) ? v[(size_t)s * d_head + tid] : 0.0f;
        acc = alpha * acc + e * v_val;

        m_prev = m_new;
        l_prev = l_new;
    }

    if (tid < d_head) {
        out[(size_t)row * d_head + tid] = (l_prev > 0.0f) ? (acc / l_prev) : 0.0f;
    }
}

/* 5. Parallel Logarithmic Reduction Tree */
__global__ void oo_k_reduce_sum(const float* in, float* out, int n) {
    __shared__ float s_warp[32];
    int tid = threadIdx.x;
    int i = blockIdx.x * (blockDim.x * 2) + tid;

    float sum = 0.0f;
    if (i < n) sum += in[i];
    if (i + blockDim.x < n) sum += in[i + blockDim.x];

    int stride = blockDim.x * 2 * gridDim.x;
    while (i + stride < n) {
        i += stride;
        sum += in[i];
        if (i + blockDim.x < n) sum += in[i + blockDim.x];
    }

    int lane = tid % 32;
    int warp_id = tid / 32;
    sum = wave32_sum(sum);
    if (lane == 0) s_warp[warp_id] = sum;
    __syncthreads();

    if (tid < 32) {
        int num_warps = (blockDim.x + 31) / 32;
        float v = (tid < num_warps) ? s_warp[tid] : 0.0f;
        v = wave32_sum(v);
        if (tid == 0) {
            atomicAdd(out, v);
        }
    }
}

/* 6. AI Acceleration: Rotary Position Embedding (RoPE) */
__global__ void oo_k_rope(const float* in, const float* cos_val, const float* sin_val, float* out, int seq_len, int dim) {
    int half_dim = dim / 2;
    int idx = (int)(blockIdx.x * blockDim.x + threadIdx.x);
    int total_pairs = seq_len * half_dim;
    if (idx >= total_pairs) return;

    int s = idx / half_dim;
    int i = idx % half_dim;

    int in_idx = s * dim + 2 * i;
    float x0 = in[in_idx];
    float x1 = in[in_idx + 1];
    float c = cos_val[idx];
    float s_v = sin_val[idx];

    out[in_idx] = x0 * c - x1 * s_v;
    out[in_idx + 1] = x0 * s_v + x1 * c;
}

/* 7. Physics & Simulation: 3D 7-Point Stencil */
__global__ void oo_k_stencil_3d(const float* in, float* out, int nx, int ny, int nz, float c0, float c1) {
    int x = (int)(blockIdx.x * blockDim.x + threadIdx.x);
    int y = (int)(blockIdx.y * blockDim.y + threadIdx.y);
    int z = (int)(blockIdx.z * blockDim.z + threadIdx.z);

    if (x >= nx || y >= ny || z >= nz) return;
    int idx = z * (nx * ny) + y * nx + x;

    if (x > 0 && x < nx - 1 && y > 0 && y < ny - 1 && z > 0 && z < nz - 1) {
        float center = in[idx];
        float sum_neighbors = in[idx - 1] + in[idx + 1]
                            + in[idx - nx] + in[idx + nx]
                            + in[idx - nx * ny] + in[idx + nx * ny];
        out[idx] = c0 * center + c1 * sum_neighbors;
    } else {
        out[idx] = in[idx];
    }
}

/* C ABI Export Wrappers */
extern "C" {

int oo_hip_vec_add_launch(const float* ha, const float* hb, float* hc, int n) {
    float *da = 0, *db = 0, *dc = 0;
    size_t bytes;
    int block, grid;
    if (!ha || !hb || !hc || n <= 0) return 1;
    bytes = (size_t)n * sizeof(float);
    if (hipMalloc((void**)&da, bytes) != hipSuccess) return 2;
    if (hipMalloc((void**)&db, bytes) != hipSuccess) { (void)hipFree(da); return 2; }
    if (hipMalloc((void**)&dc, bytes) != hipSuccess) { (void)hipFree(da); (void)hipFree(db); return 2; }
    if (hipMemcpy(da, ha, bytes, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    if (hipMemcpy(db, hb, bytes, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    block = 64;
    grid = (n + block - 1) / block;
    hipLaunchKernelGGL(oo_k_vec_add, dim3(grid, 1, 1), dim3(block, 1, 1), 0, 0, da, db, dc, n);
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) goto fail;
    if (hipMemcpy(hc, dc, bytes, hipMemcpyDeviceToHost) != hipSuccess) goto fail;
    (void)hipFree(da); (void)hipFree(db); (void)hipFree(dc);
    for (int i = 0; i < n; i++) {
        float expected = ha[i] + hb[i];
        if (fabsf(hc[i] - expected) > 1e-5f) {
            return 5;
        }
    }
    return 0;
fail:
    if (da) (void)hipFree(da); if (db) (void)hipFree(db); if (dc) (void)hipFree(dc);
    return 4;
}

int oo_hip_sgemm_launch(const float* ha, const float* hb, float* hc, int m, int n, int k) {
    float *da = 0, *db = 0, *dc = 0;
    size_t bytes_a, bytes_b, bytes_c;
    if (!ha || !hb || !hc || m <= 0 || n <= 0 || k <= 0) return 1;
    bytes_a = (size_t)m * k * sizeof(float);
    bytes_b = (size_t)k * n * sizeof(float);
    bytes_c = (size_t)m * n * sizeof(float);
    if (hipMalloc((void**)&da, bytes_a) != hipSuccess) return 2;
    if (hipMalloc((void**)&db, bytes_b) != hipSuccess) { (void)hipFree(da); return 2; }
    if (hipMalloc((void**)&dc, bytes_c) != hipSuccess) { (void)hipFree(da); (void)hipFree(db); return 2; }
    if (hipMemcpy(da, ha, bytes_a, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    if (hipMemcpy(db, hb, bytes_b, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    {
        dim3 block(TILE_DIM, TILE_DIM);
        dim3 grid((n + TILE_DIM - 1) / TILE_DIM, (m + TILE_DIM - 1) / TILE_DIM);
        hipLaunchKernelGGL(oo_k_sgemm_tiled, grid, block, 0, 0, da, db, dc, m, n, k);
    }
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) goto fail;
    if (hipMemcpy(hc, dc, bytes_c, hipMemcpyDeviceToHost) != hipSuccess) goto fail;
    (void)hipFree(da); (void)hipFree(db); (void)hipFree(dc);
    for (int r = 0; r < m; ++r) {
        for (int c = 0; c < n; ++c) {
            float acc = 0.0f;
            for (int p = 0; p < k; ++p) {
                acc += ha[r * k + p] * hb[p * n + c];
            }
            float tol = 1e-4f * (float)k;
            if (tol < 1e-4f) tol = 1e-4f;
            if (fabsf(hc[r * n + c] - acc) > tol) {
                return 5;
            }
        }
    }
    return 0;
fail:
    if (da) (void)hipFree(da); if (db) (void)hipFree(db); if (dc) (void)hipFree(dc);
    return 4;
}

int oo_hip_rmsnorm_launch(const float* hx, const float* hgamma, float* hout, int rows, int dim) {
    float *dx = 0, *dgamma = 0, *dout = 0;
    size_t bytes_x, bytes_g;
    if (!hx || !hout || rows <= 0 || dim <= 0) return 1;
    bytes_x = (size_t)rows * dim * sizeof(float);
    bytes_g = (size_t)dim * sizeof(float);
    if (hipMalloc((void**)&dx, bytes_x) != hipSuccess) return 2;
    if (hgamma) {
        if (hipMalloc((void**)&dgamma, bytes_g) != hipSuccess) { (void)hipFree(dx); return 2; }
        if (hipMemcpy(dgamma, hgamma, bytes_g, hipMemcpyHostToDevice) != hipSuccess) {
            (void)hipFree(dx); (void)hipFree(dgamma); return 4;
        }
    }
    if (hipMalloc((void**)&dout, bytes_x) != hipSuccess) {
        (void)hipFree(dx); if (dgamma) (void)hipFree(dgamma); return 2;
    }
    if (hipMemcpy(dx, hx, bytes_x, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    {
        int block_threads = (dim <= 256) ? ((dim + 31) / 32 * 32) : 256;
        if (block_threads < 32) block_threads = 32;
        hipLaunchKernelGGL(oo_k_rmsnorm, dim3(rows, 1, 1), dim3(block_threads, 1, 1), 0, 0, dx, dgamma, dout, rows, dim);
    }
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) goto fail;
    if (hipMemcpy(hout, dout, bytes_x, hipMemcpyDeviceToHost) != hipSuccess) goto fail;
    (void)hipFree(dx); if (dgamma) (void)hipFree(dgamma); (void)hipFree(dout);
    for (int r = 0; r < rows; ++r) {
        const float* rx = hx + (size_t)r * dim;
        float sum_sq = 0.0f;
        for (int d = 0; d < dim; ++d) {
            sum_sq += rx[d] * rx[d];
        }
        float inv_rms = 1.0f / sqrtf(sum_sq / (float)dim + 1e-5f);
        for (int d = 0; d < dim; ++d) {
            float ref = rx[d] * inv_rms * (hgamma ? hgamma[d] : 1.0f);
            if (fabsf(hout[r * dim + d] - ref) > 1e-3f) {
                return 5;
            }
        }
    }
    return 0;
fail:
    if (dx) (void)hipFree(dx); if (dgamma) (void)hipFree(dgamma); if (dout) (void)hipFree(dout);
    return 4;
}

int oo_hip_attention_launch(const float* hq, const float* hk, const float* hv, float* hout, int seq_len, int d_head) {
    float *dq = 0, *dk = 0, *dv = 0, *dout = 0;
    size_t bytes;
    if (!hq || !hk || !hv || !hout || seq_len <= 0 || d_head <= 0) return 1;
    if (d_head > 256) return 3; /* ERR_HEAD_DIM_BOUNDS: head_dim > 256 */
    bytes = (size_t)seq_len * d_head * sizeof(float);
    if (hipMalloc((void**)&dq, bytes) != hipSuccess) return 2;
    if (hipMalloc((void**)&dk, bytes) != hipSuccess) { (void)hipFree(dq); return 2; }
    if (hipMalloc((void**)&dv, bytes) != hipSuccess) { (void)hipFree(dq); (void)hipFree(dk); return 2; }
    if (hipMalloc((void**)&dout, bytes) != hipSuccess) { (void)hipFree(dq); (void)hipFree(dk); (void)hipFree(dv); return 2; }
    if (hipMemcpy(dq, hq, bytes, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    if (hipMemcpy(dk, hk, bytes, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    if (hipMemcpy(dv, hv, bytes, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    {
        int block_threads = d_head;
        hipLaunchKernelGGL(oo_k_attention, dim3(seq_len, 1, 1), dim3(block_threads, 1, 1), 0, 0, dq, dk, dv, dout, seq_len, d_head);
    }
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) goto fail;
    if (hipMemcpy(hout, dout, bytes, hipMemcpyDeviceToHost) != hipSuccess) goto fail;
    (void)hipFree(dq); (void)hipFree(dk); (void)hipFree(dv); (void)hipFree(dout);
    {
        float scale = 1.0f / sqrtf((float)d_head);
        float* ref_acc = (float*)malloc((size_t)d_head * sizeof(float));
        if (!ref_acc) return 4;
        for (int r = 0; r < seq_len; ++r) {
            const float* qr = hq + (size_t)r * d_head;
            float m_prev = -1e30f;
            float l_prev = 0.0f;
            for (int d = 0; d < d_head; ++d) ref_acc[d] = 0.0f;
            for (int s = 0; s < seq_len; ++s) {
                float dot = 0.0f;
                const float* ks = hk + (size_t)s * d_head;
                for (int d = 0; d < d_head; ++d) dot += qr[d] * ks[d];
                dot *= scale;
                float m_new = dot > m_prev ? dot : m_prev;
                float e = expf(dot - m_new);
                float alpha = (m_prev == -1e30f) ? 0.0f : expf(m_prev - m_new);
                l_prev = alpha * l_prev + e;
                const float* vs = hv + (size_t)s * d_head;
                for (int d = 0; d < d_head; ++d) {
                    ref_acc[d] = alpha * ref_acc[d] + e * vs[d];
                }
                m_prev = m_new;
            }
            for (int d = 0; d < d_head; ++d) {
                float ref_val = (l_prev > 0.0f) ? (ref_acc[d] / l_prev) : 0.0f;
                if (fabsf(hout[r * d_head + d] - ref_val) > 1e-3f) {
                    free(ref_acc);
                    return 5;
                }
            }
        }
        free(ref_acc);
    }
    return 0;
fail:
    if (dq) (void)hipFree(dq); if (dk) (void)hipFree(dk); if (dv) (void)hipFree(dv); if (dout) (void)hipFree(dout);
    return 4;
}

int oo_hip_reduce_sum_launch(const float* hin, float* hout, int n) {
    float *din = 0, *dout = 0;
    size_t bytes_in, bytes_out;
    if (!hin || !hout || n <= 0) return 1;
    bytes_in = (size_t)n * sizeof(float);
    bytes_out = sizeof(float);
    if (hipMalloc((void**)&din, bytes_in) != hipSuccess) return 2;
    if (hipMalloc((void**)&dout, bytes_out) != hipSuccess) { (void)hipFree(din); return 2; }
    if (hipMemset(dout, 0, bytes_out) != hipSuccess) goto fail;
    if (hipMemcpy(din, hin, bytes_in, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    {
        int block = 256;
        int grid = (n + (block * 2) - 1) / (block * 2);
        if (grid > 64) grid = 64;
        if (grid < 1) grid = 1;
        hipLaunchKernelGGL(oo_k_reduce_sum, dim3(grid, 1, 1), dim3(block, 1, 1), 0, 0, din, dout, n);
    }
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) goto fail;
    if (hipMemcpy(hout, dout, bytes_out, hipMemcpyDeviceToHost) != hipSuccess) goto fail;
    (void)hipFree(din); (void)hipFree(dout);
    {
        float ref_sum = 0.0f;
        for (int i = 0; i < n; ++i) ref_sum += hin[i];
        float tol = 1e-3f * (1.0f + fabsf(ref_sum));
        if (fabsf(*hout - ref_sum) > tol) {
            return 5;
        }
    }
    return 0;
fail:
    if (din) (void)hipFree(din); if (dout) (void)hipFree(dout);
    return 4;
}

int oo_hip_rope_launch(const float* hin, const float* hcos, const float* hsin, float* hout, int seq_len, int dim) {
    float *din = 0, *dcos = 0, *dsin = 0, *dout = 0;
    size_t bytes_data, bytes_trig;
    int total_pairs, block, grid;
    if (!hin || !hcos || !hsin || !hout || seq_len <= 0 || dim <= 0 || (dim % 2) != 0) return 1;
    bytes_data = (size_t)seq_len * dim * sizeof(float);
    bytes_trig = (size_t)seq_len * (dim / 2) * sizeof(float);
    if (hipMalloc((void**)&din, bytes_data) != hipSuccess) return 2;
    if (hipMalloc((void**)&dcos, bytes_trig) != hipSuccess) { (void)hipFree(din); return 2; }
    if (hipMalloc((void**)&dsin, bytes_trig) != hipSuccess) { (void)hipFree(din); (void)hipFree(dcos); return 2; }
    if (hipMalloc((void**)&dout, bytes_data) != hipSuccess) { (void)hipFree(din); (void)hipFree(dcos); (void)hipFree(dsin); return 2; }
    if (hipMemcpy(din, hin, bytes_data, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    if (hipMemcpy(dcos, hcos, bytes_trig, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    if (hipMemcpy(dsin, hsin, bytes_trig, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    total_pairs = seq_len * (dim / 2);
    block = 256;
    grid = (total_pairs + block - 1) / block;
    hipLaunchKernelGGL(oo_k_rope, dim3(grid, 1, 1), dim3(block, 1, 1), 0, 0, din, dcos, dsin, dout, seq_len, dim);
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) goto fail;
    if (hipMemcpy(hout, dout, bytes_data, hipMemcpyDeviceToHost) != hipSuccess) goto fail;
    (void)hipFree(din); (void)hipFree(dcos); (void)hipFree(dsin); (void)hipFree(dout);
    {
        int half_dim = dim / 2;
        for (int s = 0; s < seq_len; ++s) {
            for (int i = 0; i < half_dim; ++i) {
                int idx = s * half_dim + i;
                int in_idx = s * dim + 2 * i;
                float x0 = hin[in_idx], x1 = hin[in_idx + 1];
                float c = hcos[idx], s_v = hsin[idx];
                float ref0 = x0 * c - x1 * s_v;
                float ref1 = x0 * s_v + x1 * c;
                if (fabsf(hout[in_idx] - ref0) > 1e-4f || fabsf(hout[in_idx + 1] - ref1) > 1e-4f) {
                    return 5;
                }
            }
        }
    }
    return 0;
fail:
    if (din) (void)hipFree(din); if (dcos) (void)hipFree(dcos); if (dsin) (void)hipFree(dsin); if (dout) (void)hipFree(dout);
    return 4;
}

int oo_hip_stencil_3d_launch(const float* hin, float* hout, int nx, int ny, int nz, float c0, float c1) {
    float *din = 0, *dout = 0;
    size_t total_voxels, bytes;
    if (!hin || !hout || nx <= 0 || ny <= 0 || nz <= 0) return 1;
    total_voxels = (size_t)nx * ny * nz;
    bytes = total_voxels * sizeof(float);
    if (hipMalloc((void**)&din, bytes) != hipSuccess) return 2;
    if (hipMalloc((void**)&dout, bytes) != hipSuccess) { (void)hipFree(din); return 2; }
    if (hipMemcpy(din, hin, bytes, hipMemcpyHostToDevice) != hipSuccess) goto fail;
    {
        dim3 block(8, 8, 4);
        dim3 grid((nx + 7) / 8, (ny + 7) / 8, (nz + 3) / 4);
        hipLaunchKernelGGL(oo_k_stencil_3d, grid, block, 0, 0, din, dout, nx, ny, nz, c0, c1);
    }
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) goto fail;
    if (hipMemcpy(hout, dout, bytes, hipMemcpyDeviceToHost) != hipSuccess) goto fail;
    (void)hipFree(din); (void)hipFree(dout);
    for (int z = 0; z < nz; ++z) {
        for (int y = 0; y < ny; ++y) {
            for (int x = 0; x < nx; ++x) {
                int idx = z * (nx * ny) + y * nx + x;
                float ref_val;
                if (x > 0 && x < nx - 1 && y > 0 && y < ny - 1 && z > 0 && z < nz - 1) {
                    float center = hin[idx];
                    float sum_nb = hin[idx - 1] + hin[idx + 1]
                                 + hin[idx - nx] + hin[idx + nx]
                                 + hin[idx - nx * ny] + hin[idx + nx * ny];
                    ref_val = c0 * center + c1 * sum_nb;
                    if (fabsf(hout[idx] - ref_val) > 1e-3f) {
                        return 5;
                    }
                } else {
                    ref_val = hin[idx];
                    if (fabsf(hout[idx] - ref_val) > 1e-5f) {
                        return 5;
                    }
                }
            }
        }
    }
    return 0;
fail:
    if (din) (void)hipFree(din); if (dout) (void)hipFree(dout);
    return 4;
}

} // extern "C"
