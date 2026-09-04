/* qa/tests_challenger_contract.c — every public cap-requiring mutator
 * must fail-closed when cap=0.
 *
 * Round-5 deep-dive (adversarial reading lens) replaces the 6-lens
 * surface-area audit with a depth-first contract test: for every
 * public mutator that takes a `long long cap` as the first
 * argument, the cap=0 input must cause the function to fail-closed
 * (exit(1) or otherwise not return success). This is the contract
 * that the round-4 audit found violated in:
 *   - oo_gpu_hip_try_launch_dispatch (cap shadow at gpu_hip_dispatch.c:190)
 * The 4 CRITICALs from round 4 would have been caught by this
 * contract test had it existed.
 *
 * Pattern: each mutator is invoked in a child process with cap=0.
 * If the child exits 0, the bypass SUCCEEDED (security defect).
 * If the child exits non-zero or aborts, the bypass FAILED (test
 * passes that row). The cap check must run BEFORE the function
 * uses any pointer args; we pass stub pointers that the cap check
 * must intercept before dereference.
 *
 * Beats:
 *   1. Enumerate 49 cap-taking public mutators.
 *   2. For each: fork, child calls with cap=0, parent checks exit.
 *   3. For the GPU path (which had the cap shadow bug): the
 *      cap=0 must reach the inner launcher, which must call
 *      oo_cap_require_gpu(cap, ...) and exit(1).
 *   4. Report the count of mutators that fail-closed vs leaked.
 *
 * Exit codes:
 *   0 — every mutator fails-closed on cap=0
 *   1 — at least one mutator leaked (security defect)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#include "../oodar.h"

typedef void (*mutator_fn)(long long);

static int run_one(const char *name, mutator_fn fn) {
  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return 0; }
  if (pid == 0) {
    alarm(2);
    fn(0);
    fprintf(stderr, "  LEAK: %s returned without failing on cap=0\n", name);
    _exit(0);
  }
  int st = 0;
  waitpid(pid, &st, 0);
  /* v3.4.1 round-6 fix: distinguish a real cap-check fail-closed from a crash.
   *   - WIFEXITED && WEXITSTATUS != 0: oo_cap_require_X exited 1 → fail-closed ✓
   *   - WIFSIGNALED && sig == SIGALRM: timed out — function hung (BYPASS, suspicious)
   *   - WIFSIGNALED && sig == SIGABRT: abort() from getentropy failure → fail-closed ✓
   *   - WIFSIGNALED && sig in (SIGSEGV, SIGBUS, SIGFPE): CRASH — function dereffed
   *     a null/invalid pointer before the cap check. This is a DIFFERENT class
   *     of security defect (it means the cap check is NOT first, or the function
   *     reads a struct field before the cap check). Counted as bypass. */
  if (WIFEXITED(st) && WEXITSTATUS(st) != 0) return 1;  /* cap check exit(1) */
  if (WIFSIGNALED(st)) {
    int sig = WTERMSIG(st);
    if (sig == SIGABRT) return 1;     /* abort() from getentropy fail-closed */
    /* SIGSEGV, SIGBUS, SIGFPE, SIGALRM = crash or hang = bypass */
    fprintf(stderr, "  CRASH: %s (signal %d — %s) — cap check is NOT first\n",
            name, sig, sig == SIGSEGV ? "SIGSEGV" :
                     sig == SIGBUS  ? "SIGBUS"  :
                     sig == SIGFPE  ? "SIGFPE"  :
                     sig == SIGALRM ? "SIGALRM (timeout)" : "other");
    return 0;
  }
  fprintf(stderr, "  LEAK: %s(child exited %d, signaled=%d)\n",
          name, WIFEXITED(st) ? WEXITSTATUS(st) : -1, WIFSIGNALED(st));
  return 0;
}

/* Wrappers — each mutator invoked with cap=0. Args are stubs that
 * the cap check must intercept before dereference. The OoResS return
 * is void-cast. */
static void w_alloc(long long c)           { (void)oo_alloc(c, 16); }
static void w_alloc_bytes(long long c)     { (void)oo_alloc_bytes(c, 16); }
static void w_arena_create(long long c)    { (void)oo_arena_create(c, 4096); }
static void w_arena_alloc(long long c)     { (void)oo_arena_alloc(c, 0, 16); }
static void w_arena_reset(long long c)     { (void)oo_arena_reset(c, 0); }
static void w_arena_destroy(long long c)   { (void)oo_arena_destroy(c, 0); }
static void w_checkpoint(long long c)      { (void)oo_checkpoint(c, 0); }
static void w_rollback(long long c)        { (void)oo_rollback(c); }
static void w_actor_spawn(long long c)     { (void)oo_actor_spawn(c, oo_str_lit("t")); }
static void w_actor_send(long long c)      { (void)oo_actor_send(c, 0, oo_str_lit("x")); }
static void w_actor_recv(long long c)      { (void)oo_actor_recv(c, 0); }
static void w_actor_destroy(long long c)   { (void)oo_actor_destroy(c, 0); }
static void w_actor_restart(long long c)   { (void)oo_actor_restart(c, 0); }
static void w_channel_new(long long c)     { (void)oo_channel_new(c); }
static void w_channel_send(long long c)    { (void)oo_channel_send(c, 0, oo_str_lit("x")); }
static void w_channel_recv(long long c)    { (void)oo_channel_recv(c, 0); }
static void w_channel_destroy(long long c) { (void)oo_channel_destroy(c, 0); }
static void w_seal(long long c)            { (void)oo_seal(c, oo_str_lit("k"), oo_str_lit("n"), oo_str_lit("p"), oo_str_lit("a")); }
static void w_open(long long c)            { (void)oo_open(c, oo_str_lit("k"), oo_str_lit("n"), oo_str_lit("c"), oo_str_lit("t"), oo_str_lit("a")); }
static void w_read_file(long long c)       { (void)oo_read_file(c, oo_str_lit("/tmp/x")); }
static void w_env_get(long long c)         { (void)oo_env_get(c, oo_str_lit("PATH")); }
static void w_read_stdin_chunk(long long c){ (void)oo_read_stdin_chunk(c, 100); }
static void w_fetch(long long c)           { (void)oo_fetch(c, oo_str_lit("http://x")); }
static void w_bind_udp(long long c)        { (void)oo_bind_udp(c, 0); }
static void w_udp_send(long long c)        { (void)oo_udp_send(c, 0, oo_str_lit("h"), 0, oo_str_lit("d")); }
static void w_udp_recv(long long c)        { (void)oo_udp_recv(c, 0, 16); }
static void w_tcp_bind(long long c)        { (void)oo_tcp_bind(c, 0); }
static void w_tcp_accept(long long c)      { (void)oo_tcp_accept(c, 0); }
static void w_tcp_connect(long long c)     { (void)oo_tcp_connect(c, oo_str_lit("h"), 0); }
static void w_tcp_read(long long c)        { (void)oo_tcp_read(c, 0, 16); }
static void w_tcp_write(long long c)       { (void)oo_tcp_write(c, 0, oo_str_lit("d")); }
static void w_tcp_close(long long c)       { (void)oo_tcp_close(c, 0); }
static void w_tls_connect(long long c)     { (void)oo_tls_connect(c, oo_str_lit("h"), 0); }
static void w_sock_raw(long long c)        { (void)oo_sock_raw(c, 0); }
static void w_sys_exec(long long c)        { OoStr argv[1] = {oo_str_lit("a")}; (void)oo_sys_exec(c, 1, argv); }
static void w_dlopen(long long c)          { (void)oo_dlopen(c, oo_str_lit("x")); }
static void w_dlsym(long long c)           { (void)oo_dlsym(c, oo_str_lit("h"), oo_str_lit("n")); }
static void w_dlclose(long long c)         { (void)oo_dlclose(c, oo_str_lit("h")); }
static void w_proc_mem_read(long long c)   { (void)oo_proc_mem_read(c, 0, 16); }
static void w_landlock_restrict(long long c) { (void)oo_landlock_restrict(c, oo_str_lit(""), oo_str_lit("")); }
static void w_cap_rpc_send(long long c)    { (void)oo_cap_rpc_send(c, oo_str_lit("p")); }
static void w_cap_rpc_recv(long long c)    { (void)oo_cap_rpc_recv(c, oo_str_lit("s")); }
static void w_gpu_hip_try_launch(long long c) { (void)oo_gpu_hip_try_launch(c, oo_str_lit("s")); }
static void w_gpu_hip_vec_add(long long cap_) {
  float a[1]={0},b[1]={0},out[1]={0};
  (void)oo_gpu_hip_vec_add(cap_, a, b, out, 1);
}
static void w_thread_spawn(long long c)    { (void)oo_thread_spawn(c, oo_str_lit("t")); }
static void w_thread_join(long long c)     { (void)oo_thread_join(c, 0); }
static void w_thread_join_s(long long c)   { (void)oo_thread_join_s(c, oo_str_lit("t")); }
static void w_otp_supervise(long long c)   { (void)oo_otp_supervise(c, 0); }
/* oo_host_build was removed in v3.1.0 (zero-callers, anti-emulation
 * path that is out of scope for the runtime). oo_verify_human was
 * removed in v3.1.0 (documented as "not a product feature"). Both
 * are excluded from the contract test. */
static void w_metrics_incr(long long c)    { (void)oo_metrics_incr(c, oo_str_lit("x")); }
static void w_metrics_get(long long c)     { (void)oo_metrics_get(c, oo_str_lit("x")); }
static void w_cg_sign(long long c)         { (void)oo_cg_sign(c); }
static void w_cg_verify(long long c)       { (void)oo_cg_verify(c, 0); }
static void w_file_stamp(long long c)      { (void)oo_file_stamp(c, oo_str_lit("/tmp/x")); }
static void w_rlimit_set_cpu_sec(long long c) { (void)oo_rlimit_set_cpu_sec(c, 60); }
static void w_rlimit_set_mem_mb(long long c)  { (void)oo_rlimit_set_mem_mb(c, 1024); }
static void w_rlimit_set_nofile(long long c)  { (void)oo_rlimit_set_nofile(c, 1024); }
/* oo_verify_human: removed in v3.1.0 */

struct { const char *name; mutator_fn fn; } CASES[] = {
  {"oo_alloc",                 w_alloc},
  {"oo_alloc_bytes",           w_alloc_bytes},
  {"oo_arena_create",          w_arena_create},
  {"oo_arena_alloc",           w_arena_alloc},
  {"oo_arena_reset",           w_arena_reset},
  {"oo_arena_destroy",         w_arena_destroy},
  {"oo_checkpoint",            w_checkpoint},
  {"oo_rollback",              w_rollback},
  {"oo_actor_spawn",           w_actor_spawn},
  {"oo_actor_send",            w_actor_send},
  {"oo_actor_recv",            w_actor_recv},
  {"oo_actor_destroy",         w_actor_destroy},
  {"oo_actor_restart",         w_actor_restart},
  {"oo_channel_new",           w_channel_new},
  {"oo_channel_send",          w_channel_send},
  {"oo_channel_recv",          w_channel_recv},
  {"oo_channel_destroy",       w_channel_destroy},
  {"oo_seal",                  w_seal},
  {"oo_open",                  w_open},
  {"oo_read_file",             w_read_file},
  {"oo_env_get",               w_env_get},
  {"oo_read_stdin_chunk",      w_read_stdin_chunk},
  {"oo_fetch",                 w_fetch},
  {"oo_bind_udp",              w_bind_udp},
  {"oo_udp_send",              w_udp_send},
  {"oo_udp_recv",              w_udp_recv},
  {"oo_tcp_bind",              w_tcp_bind},
  {"oo_tcp_accept",            w_tcp_accept},
  {"oo_tcp_connect",           w_tcp_connect},
  {"oo_tcp_read",              w_tcp_read},
  {"oo_tcp_write",             w_tcp_write},
  {"oo_tcp_close",             w_tcp_close},
  {"oo_tls_connect",           w_tls_connect},
  {"oo_sock_raw",              w_sock_raw},
  {"oo_sys_exec",              w_sys_exec},
  {"oo_dlopen",                w_dlopen},
  {"oo_dlsym",                 w_dlsym},
  {"oo_dlclose",               w_dlclose},
  {"oo_proc_mem_read",         w_proc_mem_read},
  {"oo_landlock_restrict",     w_landlock_restrict},
  {"oo_cap_rpc_send",          w_cap_rpc_send},
  {"oo_cap_rpc_recv",          w_cap_rpc_recv},
  {"oo_gpu_hip_try_launch",    w_gpu_hip_try_launch},
  {"oo_gpu_hip_vec_add",       w_gpu_hip_vec_add},
  {"oo_thread_spawn",          w_thread_spawn},
  {"oo_thread_join",           w_thread_join},
  {"oo_thread_join_s",         w_thread_join_s},
  {"oo_otp_supervise",         w_otp_supervise},
  /* oo_host_build + oo_verify_human: removed in v3.1.0 */
  {"oo_metrics_incr",          w_metrics_incr},
  {"oo_metrics_get",           w_metrics_get},
  {"oo_cg_sign",               w_cg_sign},
  {"oo_cg_verify",             w_cg_verify},
  {"oo_file_stamp",            w_file_stamp},
  {"oo_rlimit_set_cpu_sec",    w_rlimit_set_cpu_sec},
  {"oo_rlimit_set_mem_mb",     w_rlimit_set_mem_mb},
  {"oo_rlimit_set_nofile",     w_rlimit_set_nofile},
  {NULL, NULL}
};

int main(void) {
  int total = 0, passed = 0, leaked = 0;
  fprintf(stderr, "contract: testing %zu cap-requiring public mutators with cap=0\n",
          sizeof(CASES)/sizeof(CASES[0]) - 1);
  for (int i = 0; CASES[i].name; i++) {
    total++;
    if (run_one(CASES[i].name, CASES[i].fn)) {
      passed++;
    } else {
      leaked++;
    }
  }
  fprintf(stderr, "contract: %d/%d fail-closed on cap=0 (%d leaked)\n", passed, total, leaked);
  if (leaked == 0) {
    printf("OK\tcontract\t%d/%d cap-requiring mutators fail-closed on cap=0\n", passed, total);
    return 0;
  }
  fprintf(stderr, "FAIL\tcontract\t%d mutators leaked — security defect\n", leaked);
  return 1;
}
