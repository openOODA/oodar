/* sys_residual.c — official refuse for process/sys ops not yet Layer 1.
 * Cap check runs first. Then Err. Not implemented in this Floor. */
#include "../../oodar.h"

static OoResS oo_sys_res_miss(const char *m) {
  OoResS r;
  r.ok = 0;
  r.val = oo_str_lit(m);
  return r;
}

OoResS oo_sys_spawn(long long cap, OoStr cmd) {
  (void)cmd;
  oo_cap_require_process(cap, "sys_spawn");
  return oo_sys_res_miss("sys_spawn residual");
}

OoResS oo_sys_wait(long long cap, long long pid) {
  (void)pid;
  oo_cap_require_process(cap, "sys_wait");
  return oo_sys_res_miss("sys_wait residual");
}

OoResS oo_sys_kill(long long cap, long long pid, long long sig) {
  (void)pid;
  (void)sig;
  oo_cap_require_process(cap, "sys_kill");
  return oo_sys_res_miss("sys_kill residual");
}

OoResS oo_sys_epoll_create(long long cap, long long flags) {
  (void)flags;
  oo_cap_require_sys(cap, "sys_epoll_create");
  return oo_sys_res_miss("epoll residual");
}

OoResS oo_sys_inotify_init(long long cap) {
  oo_cap_require_sys(cap, "sys_inotify_init");
  return oo_sys_res_miss("inotify residual");
}

OoResS oo_sys_prctl(long long cap, long long op) {
  (void)op;
  oo_cap_require_sys(cap, "sys_prctl");
  return oo_sys_res_miss("prctl residual");
}
