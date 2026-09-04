/* M161/M162: ThreadCap/GpuCap + process residual; pthread mutex path A.
 * Joinable threads: see chs_rt_thread.c (M163). */
#include "chs_rt.h"
#include <unistd.h>
#include <pthread.h>

/* CAP-G4: ProcessCap OR SysCap. spawn/wait/kill are real fork/waitpid/kill. */
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
void oo_cap_require_process(long long got, const char *op);
/* sys_spawn: refuses to take a shell command string. Use sys_exec with argv. */
OoResS oo_sys_spawn(long long cap, OoStr cmd) {
  OoResS r;
  (void)cmd;
  oo_cap_require_process(cap, "sys_spawn");
  r.ok = 0;
  r.val = oo_str_lit("sys_spawn removed: use sys_exec with argv (no shell)");
  return r;
}
OoResS oo_sys_wait(long long cap, long long pid) {
  OoResS r;
  int st;
  char stbuf[32];
  pid_t w;
  oo_cap_require_process(cap, "sys_wait");
  r.ok = 0;
  r.val = oo_str_lit("sys_wait failed");
  if (pid == 0) return r;
  w = waitpid((pid_t)pid, &st, 0);
  if (w < 0) return r;
  r.ok = 1;
  if (WIFEXITED(st)) {
    snprintf(stbuf, sizeof stbuf, "%d", WEXITSTATUS(st));
  } else if (WIFSIGNALED(st)) {
    snprintf(stbuf, sizeof stbuf, "sig:%d", WTERMSIG(st));
  } else {
    snprintf(stbuf, sizeof stbuf, "st:%d", st);
  }
  r.val = oo_str_lit(stbuf);
  return r;
}
OoResS oo_sys_kill(long long cap, long long pid, long long sig) {
  OoResS r;
  oo_cap_require_process(cap, "sys_kill");
  r.ok = 0;
  r.val = oo_str_lit("sys_kill failed");
  if (pid <= 0 || sig < 0 || sig > 64) return r;
  if (kill((pid_t)pid, (int)sig) != 0) return r;
  r.ok = 1;
  r.val = oo_str_lit("");
  return r;
}

/* M166 path A: OS syscall free names — SysCap require then residual Err.
 * Honesty: not full async I/O / epoll loop / inotify watches / prctl product. */
OoResS oo_sys_epoll_create(long long cap, long long flags) {
  OoResS r;
  oo_cap_require_sys(cap, "sys_epoll_create");
  r.ok = 0;
  r.val = oo_str_lit("sys_epoll_create residual: not full async I/O");
  (void)flags;
  return r;
}
OoResS oo_sys_inotify_init(long long cap) {
  OoResS r;
  oo_cap_require_sys(cap, "sys_inotify_init");
  r.ok = 0;
  r.val = oo_str_lit("sys_inotify_init residual: path A seal only");
  return r;
}
OoResS oo_sys_prctl(long long cap, long long option) {
  OoResS r;
  oo_cap_require_sys(cap, "sys_prctl");
  r.ok = 0;
  r.val = oo_str_lit("sys_prctl residual: path A seal only");
  (void)option;
  return r;
}

#define OO_MUTEX_SLOTS 64
static pthread_mutex_t g_mutexes[OO_MUTEX_SLOTS];
static int g_mutex_inited[OO_MUTEX_SLOTS];
static pthread_mutex_t g_mutex_boot = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t *mutex_for(long long mid) {
  unsigned idx = (unsigned)(mid < 0 ? -mid : mid) % OO_MUTEX_SLOTS;
  pthread_mutex_lock(&g_mutex_boot);
  if (!g_mutex_inited[idx]) {
    pthread_mutex_init(&g_mutexes[idx], NULL);
    g_mutex_inited[idx] = 1;
  }
  pthread_mutex_unlock(&g_mutex_boot);
  return &g_mutexes[idx];
}

OoResS oo_mutex_lock(long long cap, long long mid) {
  OoResS r;
  oo_cap_require_thread(cap, "mutex_lock");
  if (pthread_mutex_lock(mutex_for(mid)) != 0) {
    r.ok = 0;
    r.val = oo_str_lit("mutex_lock failed");
    return r;
  }
  r.ok = 1;
  r.val = oo_str_lit("locked");
  return r;
}
OoResS oo_mutex_unlock(long long cap, long long mid) {
  OoResS r;
  oo_cap_require_thread(cap, "mutex_unlock");
  if (pthread_mutex_unlock(mutex_for(mid)) != 0) {
    r.ok = 0;
    r.val = oo_str_lit("mutex_unlock failed");
    return r;
  }
  r.ok = 1;
  r.val = oo_str_lit("unlocked");
  return r;
}

/* M165 Path A: HIP/ROCm only; no "noop"/"cpu:" fallbacks. Empty shader or unknown
   prefix fails closed. */
OoResS oo_gpu_launch(long long cap, OoStr shader) {
  OoResS r;
  const char *p;
  long long len;
  oo_cap_require_gpu(cap, "gpu_launch");
  p = shader.data ? shader.data : "";
  len = shader.len;
  if (len < 0) len = 0;
  /* HIP/ROCm: real device path when libamdhip64 is present; else residual. */
  if ((len >= 4 && strncmp(p, "hip:", 4) == 0) || (len >= 5 && strncmp(p, "rocm:", 5) == 0)) {
    return oo_gpu_hip_try_launch(cap, shader);
  }
  /* Empty shader, "noop", "cpu:", PTX, SPIR-V, Metal, etc. all fail closed. There is
     no CPU-shaped substitute for a GPU launch. */
  r.ok = 0;
  r.val = oo_str_lit("gpu residual: no device shaders");
  return r;
}
