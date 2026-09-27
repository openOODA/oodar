/* qa/tests_cuda_nogpu.c — CUDA dispatch coherence without a GPU.
 *
 * CI-safe (in CHALLENGERS): asserts the dispatch layer fails closed
 * coherently in ANY environment. Invalid-args rows always fail;
 * valid-args rows return either clean-absent (no liboo_cuda.so) or
 * clean-match (GPU + .so present) — never a crash, never a lie.
 * oo_gpu_cuda_available() must not crash and must return 0/1.
 *
 * Exit codes: 0 — all rows pass. 1 — any row fails.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../oodar.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
  else { printf("ok: %s\n", msg); } \
} while (0)

static int has(OoStr s, const char *sub) {
  if (!s.data || s.len <= 0) return 0;
  for (long long i = 0; i + (long long)strlen(sub) <= s.len; i++)
    if (memcmp(s.data + i, sub, strlen(sub)) == 0) return 1;
  return 0;
}

int main(void) {
  long long cap = oo_cap_grant_gpu();
  int av = oo_gpu_cuda_available();
  CHECK(av == 0 || av == 1, "available() returns 0/1");

  float a[8] = {1, 2, 3, 4, 5, 6, 7, 8}, b[8] = {1, 1, 1, 1, 1, 1, 1, 1}, c[8];
  OoResS r = oo_gpu_cuda_vec_add(cap, 0, b, c, 8);
  CHECK(r.ok == 0 && has(r.val, "invalid args"), "null fails closed (invalid args)");
  r = oo_gpu_cuda_vec_add(cap, a, b, c, 0);
  CHECK(r.ok == 0 && has(r.val, "invalid args"), "zero n fails closed");
  r = oo_gpu_cuda_sgemm(cap, a, b, c, 0, 2, 2);
  CHECK(r.ok == 0 && has(r.val, "invalid args"), "sgemm zero dim fails closed");
  r = oo_gpu_cuda_reduce_sum(cap, 0, c, 8);
  CHECK(r.ok == 0 && has(r.val, "invalid args"), "reduce null fails closed");

  OoFloatBuf ba = oo_float_buf_new(8, 8), sh = oo_float_buf_new(4, 4);
  r = oo_gpu_cuda_vec_add_buf(cap, ba, sh, ba);
  CHECK(r.ok == 0 && has(r.val, "length mismatch"), "buf length mismatch fails closed");
  OoFloatBuf zb = oo_float_buf_new(8, 8);
  zb.len = 0;
  r = oo_gpu_cuda_vec_add_buf(cap, ba, ba, zb);
  CHECK(r.ok == 0 && has(r.val, "zero len"), "buf zero len fails closed");

  /* Valid args: absent or match, coherently. */
  r = oo_gpu_cuda_vec_add(cap, a, b, c, 8);
  int coherent = (r.ok == 0 && has(r.val, "liboo_cuda.so absent")) ||
                 (r.ok == 1 && has(r.val, "MATCH"));
  CHECK(coherent, "valid args coherent (absent|MATCH)");
  r = oo_gpu_cuda_reduce_sum(cap, a, c, 8);
  coherent = (r.ok == 0 && has(r.val, "liboo_cuda.so absent")) ||
             (r.ok == 1 && has(r.val, "MATCH"));
  CHECK(coherent, "reduce valid args coherent (absent|MATCH)");

  free(ba.data); free(sh.data); free(zb.data);
  if (fails == 0) printf("PASS tests_cuda_nogpu\n");
  return fails ? 1 : 0;
}
