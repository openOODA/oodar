/* qa/tests_adversarial_gpu_cap.c — adversarial testing of GPU capabilities.
 *
 * Verifies that all GPU entry points strictly enforce GpuCap verification
 * and trap / fail-closed immediately under null (0) or forged capability tokens.
 *
 * Exit codes: 0 — all checks pass; 1 — any check fails.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#include "../oodar.h"
#include "../hw/gpu/gpu.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
  else { printf("ok: %s\n", msg); } \
} while (0)

typedef void (*adversarial_case_fn)(long long);

static int run_adversarial_child(adversarial_case_fn fn, long long cap) {
  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return 0; }
  if (pid == 0) {
    alarm(2);
    fn(cap);
    /* If the function returned cleanly without trapping, this is a security failure */
    _exit(0);
  }
  int st = 0;
  waitpid(pid, &st, 0);
  /* Fail-closed expectation: child process terminated with non-zero exit code or signal */
  if (WIFEXITED(st) && WEXITSTATUS(st) != 0) return 1;
  if (WIFSIGNALED(st)) return 1;
  return 0;
}

static void t_launch_kernel(long long cap) {
  void *args[1] = { 0 };
  oo_gpu_launch_kernel(cap, oo_str_lit("hip:"), oo_str_lit("k"), oo_str_lit(""), 1, 1, 1, 1, 1, 1, args, 1);
}

static void t_copy_h2d(long long cap) {
  char buf[8] = {0};
  oo_gpu_copy_h2d(cap, 1, buf, 8);
}

static void t_copy_d2h(long long cap) {
  char buf[8] = {0};
  oo_gpu_copy_d2h(cap, buf, 1, 8);
}

static void t_copy_h2d_async(long long cap) {
  char buf[8] = {0};
  oo_gpu_copy_h2d_async(cap, 1, buf, 8, 1);
}

static void t_copy_d2h_async(long long cap) {
  char buf[8] = {0};
  oo_gpu_copy_d2h_async(cap, buf, 1, 8, 1);
}

static void t_cuda_vec_add(long long cap) {
  float a[4] = {1}, b[4] = {1}, c[4] = {0};
  oo_gpu_cuda_vec_add(cap, a, b, c, 4);
}

static void t_stream_create(long long cap) {
  oo_gpu_stream_create(cap, 0);
}

static void t_stream_destroy(long long cap) {
  oo_gpu_stream_destroy(cap, 1);
}

static void t_sync(long long cap) {
  oo_gpu_sync(cap);
}

int main(void) {
  printf("Running tests_adversarial_gpu_cap...\n");

  /* Null token (cap = 0) */
  CHECK(run_adversarial_child(t_launch_kernel, 0), "launch_kernel traps on cap=0");
  CHECK(run_adversarial_child(t_copy_h2d, 0), "copy_h2d traps on cap=0");
  CHECK(run_adversarial_child(t_copy_d2h, 0), "copy_d2h traps on cap=0");
  CHECK(run_adversarial_child(t_copy_h2d_async, 0), "copy_h2d_async traps on cap=0");
  CHECK(run_adversarial_child(t_copy_d2h_async, 0), "copy_d2h_async traps on cap=0");
  CHECK(run_adversarial_child(t_cuda_vec_add, 0), "cuda_vec_add traps on cap=0");
  CHECK(run_adversarial_child(t_stream_create, 0), "stream_create traps on cap=0");
  CHECK(run_adversarial_child(t_stream_destroy, 0), "stream_destroy traps on cap=0");
  CHECK(run_adversarial_child(t_sync, 0), "gpu_sync traps on cap=0");

  /* Forged token (cap = 0xdeadbeefcafeULL) */
  long long forged = (long long)0xdeadbeefcafeULL;
  CHECK(run_adversarial_child(t_launch_kernel, forged), "launch_kernel traps on forged cap");
  CHECK(run_adversarial_child(t_copy_h2d, forged), "copy_h2d traps on forged cap");
  CHECK(run_adversarial_child(t_copy_d2h, forged), "copy_d2h traps on forged cap");
  CHECK(run_adversarial_child(t_cuda_vec_add, forged), "cuda_vec_add traps on forged cap");

  if (fails == 0) printf("PASS tests_adversarial_gpu_cap\n");
  return fails ? 1 : 0;
}
