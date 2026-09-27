/* qa/oo_cuda_so_smoke.c — full-API CUDA verification on NVIDIA hardware.
 * NVIDIA twin of oo_hip_so_smoke.c, but through the oodar API surface
 * (caps + dispatch), not raw dlopen. MANUAL: needs liboo_cuda.so +
 * NVIDIA GPU; NOT in CHALLENGERS (mirrors the HIP smoke). Build:
 *   nvcc -shared -Xcompiler -fPIC -O2 -arch=sm_89 -o liboo_cuda.so hw/gpu/cuda_kern.cu
 *   gcc -O2 -I. -o /tmp/cu_smoke qa/oo_cuda_so_smoke.c oodar.c -lpthread -ldl -lm
 *   OODA_CUDA_LIB=<path>/liboo_cuda.so /tmp/cu_smoke
 * Exit 0 iff all 6 dispatchers MATCH with spot-checked values.
 * Exit 2 (SKIP) when no CUDA driver is present. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "../oodar.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
  else { printf("ok: %s\n", msg); } \
} while (0)

int main(void) {
  long long cap = oo_cap_grant_gpu();
  if (!oo_gpu_cuda_available()) {
    printf("SKIP: no CUDA driver (libcuda.so.1 absent)\n");
    return 2;
  }
  CHECK(oo_gpu_cuda_load() == 1, "liboo_cuda.so binds");

  float a[64], b[64], c[64];
  for (int i = 0; i < 64; i++) { a[i] = (float)i; b[i] = 2.0f * (float)i; c[i] = 0.0f; }
  OoResS r = oo_gpu_cuda_vec_add(cap, a, b, c, 64);
  CHECK(r.ok == 1, "vec_add MATCH");
  CHECK(fabsf(c[63] - 189.0f) < 1e-4f, "vec_add c[63]==189");

  OoFloatBuf ba = oo_float_buf_new(64, 64), bb = oo_float_buf_new(64, 64), bc = oo_float_buf_new(64, 64);
  for (int i = 0; i < 64; i++) { ba.data[i] = (float)i; bb.data[i] = 1.0f; bc.data[i] = 0.0f; }
  r = oo_gpu_cuda_vec_add_buf(cap, ba, bb, bc);
  CHECK(r.ok == 1, "vec_add_buf MATCH");
  CHECK(fabsf(bc.data[63] - 64.0f) < 1e-4f, "vec_add_buf bc[63]==64");

  float m1[16], m2[16], m3[16];
  for (int i = 0; i < 16; i++) { m1[i] = (float)(i + 1); m2[i] = (i % 5 == 0) ? 1.0f : 0.0f; m3[i] = 0.0f; }
  r = oo_gpu_cuda_sgemm(cap, m1, m2, m3, 4, 4, 4);
  CHECK(r.ok == 1, "sgemm MATCH (x identity)");
  CHECK(fabsf(m3[10] - 11.0f) < 1e-3f, "sgemm m3[10]==11");

  float x[8] = {1, 2, 3, 4, 5, 6, 7, 8}, g[4] = {1, 1, 1, 1}, o[8];
  r = oo_gpu_cuda_rmsnorm(cap, x, g, o, 2, 4);
  CHECK(r.ok == 1, "rmsnorm MATCH");
  float inv = 1.0f / sqrtf((1 + 4 + 9 + 16) / 4.0f + 1e-6f);
  CHECK(fabsf(o[0] - 1.0f * inv) < 1e-3f, "rmsnorm o[0] spot check");

  float q[16], k[16], v[16], ao[16];
  for (int i = 0; i < 16; i++) { q[i] = 0.1f * (float)(i % 4); k[i] = 0.1f * (float)i; v[i] = (float)i; }
  r = oo_gpu_cuda_attention(cap, q, k, v, ao, 4, 4);
  CHECK(r.ok == 1, "attention MATCH");

  float big[4096], sum[1] = {0};
  for (int i = 0; i < 4096; i++) big[i] = 1.0f;
  r = oo_gpu_cuda_reduce_sum(cap, big, sum, 4096);
  CHECK(r.ok == 1, "reduce_sum MATCH");
  CHECK(fabsf(sum[0] - 4096.0f) < 1.0f, "reduce_sum == 4096");

  double fxa[64], fxb[64], fxc[64];
  OoFList fx, fy, fz;
  for (int i = 0; i < 64; i++) { fxa[i] = (double)i; fxb[i] = 1.0; fxc[i] = 0.0; }
  fx.data = fxa; fx.len = 64; fx.cap = 64;
  fy.data = fxb; fy.len = 64; fy.cap = 64;
  fz.data = fxc; fz.len = 64; fz.cap = 64;
  r = oo_gpu_cuda_vec_add_flist(cap, fx, fy, fz, 64);
  CHECK(r.ok == 1, "vec_add_flist MATCH (LLVM byval path)");
  CHECK(fabs(fxc[63] - 64.0) < 1e-6, "flist fxc[63]==64");

  OoStr sh = oo_str_lit("cuda:vec_add");
  r = oo_gpu_cuda_try_launch(cap, sh);
  CHECK(r.ok == 1, "try_launch cuda:vec_add MATCH");
  sh = oo_str_lit("cuda:reduce");
  r = oo_gpu_cuda_try_launch(cap, sh);
  CHECK(r.ok == 1, "try_launch cuda:reduce MATCH");
  sh = oo_str_lit("cuda:nope");
  r = oo_gpu_cuda_try_launch(cap, sh);
  CHECK(r.ok == 0, "try_launch unknown kernel fails closed");
  sh = oo_str_lit("hip:vec_add");
  r = oo_gpu_cuda_try_launch(cap, sh);
  CHECK(r.ok == 0, "try_launch wrong prefix fails closed");

  /* Fail-closed rows (valid with or without GPU). */
  r = oo_gpu_cuda_vec_add(cap, 0, b, c, 64);
  CHECK(r.ok == 0, "vec_add null fails closed");
  OoFloatBuf short_b = oo_float_buf_new(32, 32);
  r = oo_gpu_cuda_vec_add_buf(cap, ba, short_b, bc);
  CHECK(r.ok == 0, "vec_add_buf length mismatch fails closed");

  free(ba.data); free(bb.data); free(bc.data); free(short_b.data);
  if (fails == 0) printf("PASS oo_cuda_so_smoke (sm_89)\n");
  return fails ? 1 : 0;
}
