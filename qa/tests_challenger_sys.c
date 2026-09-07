/* qa/tests_challenger_sys.c — cap=0 fail-closed for new sys ABI.
 * Double-run via Makefile. Child must not return success. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
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
  if (WIFEXITED(st) && WEXITSTATUS(st) != 0) return 1;
  if (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT) return 1;
  fprintf(stderr, "  CRASH_OR_LEAK: %s\n", name);
  return 0;
}

static void w_spawn(long long c) { (void)oo_sys_spawn(c, oo_str_lit("true")); }
static void w_wait(long long c) { (void)oo_sys_wait(c, 1); }
static void w_kill(long long c) { (void)oo_sys_kill(c, 1, 9); }
static void w_epoll(long long c) { (void)oo_sys_epoll_create(c, 0); }
static void w_inotify(long long c) { (void)oo_sys_inotify_init(c); }
static void w_prctl(long long c) { (void)oo_sys_prctl(c, 1); }
static void w_exec_wait(long long c) {
  (void)oo_sys_exec_wait(c, oo_str_lit("/bin/true"), oo_slist_new());
}

struct { const char *name; mutator_fn fn; } CASES[] = {
  {"oo_sys_spawn", w_spawn},
  {"oo_sys_wait", w_wait},
  {"oo_sys_kill", w_kill},
  {"oo_sys_epoll_create", w_epoll},
  {"oo_sys_inotify_init", w_inotify},
  {"oo_sys_prctl", w_prctl},
  {"oo_sys_exec_wait", w_exec_wait},
  {NULL, NULL}
};

int main(void) {
  int total = 0, passed = 0, leaked = 0;
  for (int i = 0; CASES[i].name; i++) {
    total++;
    if (run_one(CASES[i].name, CASES[i].fn)) passed++;
    else leaked++;
  }
  if (leaked == 0) {
    printf("OK\tsys\t%d/%d cap=0 fail-closed\n", passed, total);
    return 0;
  }
  fprintf(stderr, "FAIL\tsys\t%d leaked\n", leaked);
  return 1;
}
