/* Named chs_cap_* seccomp-bpf: unauthorized socket/connect/bind, fork/execve
 * /process clone, and openat write-mode are SECCOMP_RET_KILL_PROCESS.
 * clone3 stays ENOSYS without ProcessCap so glibc pthread falls back to clone. */
#include "chs_rt.h"
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#if defined(__linux__)
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <fcntl.h>
#endif

#ifndef CHS_CAP_NET
#define CHS_CAP_NET 1u
#define CHS_CAP_PROCESS 2u
#define CHS_CAP_FSWRITE 4u
#define CHS_CAP_FSREAD 8u
#define CHS_CAP_SYS 16u
#define CHS_CAP_FS 32u
#endif

#ifndef OO_OPEN_WRITE_BITS
#define OO_OPEN_WRITE_BITS (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)
#endif

static pthread_mutex_t g_capf_mu = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_capf_mask;
static unsigned char g_capf_tok[32];
static int g_capf_on;
static int g_capf_avail = -1;

void chs_cap_init(void) {
  pthread_mutex_lock(&g_capf_mu);
  g_capf_mask = 0;
  memset(g_capf_tok, 0, sizeof g_capf_tok);
  g_capf_on = 0;
  pthread_mutex_unlock(&g_capf_mu);
}

void chs_cap_drop(void) {
  pthread_mutex_lock(&g_capf_mu);
  crypto_secure_wipe(&g_capf_mask, sizeof g_capf_mask);
  crypto_secure_wipe(g_capf_tok, sizeof g_capf_tok);
  g_capf_mask = 0;
  g_capf_on = 0;
  pthread_mutex_unlock(&g_capf_mu);
}

int chs_cap_is_sandboxed(void) {
  int on;
  pthread_mutex_lock(&g_capf_mu);
  on = g_capf_on;
  pthread_mutex_unlock(&g_capf_mu);
  return on;
}

#if defined(__linux__) && defined(PR_SET_SECCOMP)
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif

static int capf_install(uint32_t net_act, uint32_t proc_act, uint32_t clone3_act, int fsw_ok) {
  struct sock_filter f[64];
  unsigned n = 0;
  struct sock_fprog prog;
  int rc;
#define F_STMT(c, k) do { f[n++] = (struct sock_filter)BPF_STMT((c), (k)); } while (0)
#define F_JUMP(c, k, jt, jf) do { f[n++] = (struct sock_filter)BPF_JUMP((c), (k), (jt), (jf)); } while (0)
  F_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr));
#ifdef __NR_socket
  F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1);
  F_STMT(BPF_RET | BPF_K, net_act);
#endif
#ifdef __NR_connect
  F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1);
  F_STMT(BPF_RET | BPF_K, net_act);
#endif
#ifdef __NR_bind
  F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1);
  F_STMT(BPF_RET | BPF_K, net_act);
#endif
#ifdef __NR_fork
  F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1);
  F_STMT(BPF_RET | BPF_K, proc_act);
#endif
#ifdef __NR_vfork
  F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 0, 1);
  F_STMT(BPF_RET | BPF_K, proc_act);
#endif
#ifdef __NR_execve
  F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1);
  F_STMT(BPF_RET | BPF_K, proc_act);
#endif
#ifdef __NR_execveat
  F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1);
  F_STMT(BPF_RET | BPF_K, proc_act);
#endif
#ifdef __NR_clone3
  F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1);
  F_STMT(BPF_RET | BPF_K, clone3_act);
#endif
#ifdef __NR_clone
  F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4);
  F_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, args[0]));
  F_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 0, 1);
  F_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  F_STMT(BPF_RET | BPF_K, proc_act);
#endif
  if (!fsw_ok) {
#ifdef __NR_openat
    F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 4);
    F_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, args[2]));
    F_JUMP(BPF_JMP | BPF_JSET | BPF_K, (uint32_t)OO_OPEN_WRITE_BITS, 0, 1);
    F_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    F_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
#endif
#ifdef __NR_open
    F_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 4);
    F_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, args[1]));
    F_JUMP(BPF_JMP | BPF_JSET | BPF_K, (uint32_t)OO_OPEN_WRITE_BITS, 0, 1);
    F_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    F_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
#endif
  }
  F_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
#undef F_STMT
#undef F_JUMP
  if (n > (unsigned)(sizeof f / sizeof f[0])) return -2;
  prog.len = (unsigned short)n;
  prog.filter = f;
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    if (errno == ENOSYS || errno == EINVAL) return -1;
  }
#ifdef __NR_seccomp
  rc = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  if (rc == 0) return 0;
#endif
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
    if (errno == ENOSYS || errno == EPERM || errno == EINVAL) return -1;
    fprintf(stderr, "ERR\tcap\tseccomp apply failed errno=%d\n", errno);
    return -2;
  }
  return 0;
}
#endif

int chs_cap_apply_seccomp_filter(uint32_t allowed_caps_mask) {
  int rc = 0;
  pthread_mutex_lock(&g_capf_mu);
  if (g_capf_on) {
    pthread_mutex_unlock(&g_capf_mu);
    return 0;
  }
  g_capf_mask = allowed_caps_mask;
  memcpy(g_capf_tok, &allowed_caps_mask, sizeof allowed_caps_mask);
#if defined(__linux__) && defined(PR_SET_SECCOMP)
  {
    int proc_ok = (allowed_caps_mask & (CHS_CAP_PROCESS | CHS_CAP_SYS)) != 0;
    int fsw_ok = (allowed_caps_mask & (CHS_CAP_FSWRITE | CHS_CAP_FS)) != 0;
    uint32_t net_act = (allowed_caps_mask & CHS_CAP_NET) ? SECCOMP_RET_ALLOW : SECCOMP_RET_KILL_PROCESS;
    uint32_t proc_act = proc_ok ? SECCOMP_RET_ALLOW : SECCOMP_RET_KILL_PROCESS;
    uint32_t clone3_act = proc_ok ? SECCOMP_RET_ALLOW : (SECCOMP_RET_ERRNO | ENOSYS);
    rc = capf_install(net_act, proc_act, clone3_act, fsw_ok);
  }
  if (rc == 0) {
    g_capf_on = 1;
    g_capf_avail = 1;
  } else if (rc == -1) {
    g_capf_avail = 0;
    fprintf(stderr, "ERR\tcap\tseccomp ABI unavailable\n");
  }
#else
  g_capf_avail = 0;
  rc = -1;
  fprintf(stderr, "ERR\tcap\tseccomp ABI unavailable\n");
#endif
  pthread_mutex_unlock(&g_capf_mu);
  return rc;
}
