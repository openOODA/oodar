/* sys_epoll.c — Epoll, timerfd, and eventfd multiplexing under SysCap.
 *
 * Implements:
 *   oo_sys_epoll_create1: epoll_create1(2)
 *   oo_sys_epoll_ctl: epoll_ctl(2) ADD, MOD, DEL
 *   oo_sys_epoll_wait: epoll_wait(2) returning formatted event string
 *   oo_sys_close: close(2) for event descriptors
 *   oo_sys_timerfd_create: timerfd_create(2) monotonic high-res timer
 *   oo_sys_timerfd_settime: timerfd_settime(2) periodic or one-shot
 *   oo_sys_eventfd: eventfd(2) inter-thread notification
 *
 * Governed by RULES.oot <= 256 lines and zero ambient authority.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../../oodar.h"
#include "../../oodar_internal.h"
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

OoResI oo_sys_epoll_create1(long long cap, long long flags) {
  OoResI r;
  oo_cap_require_sys(cap, "sys_epoll_create1");
  r.ok = 0; r.val = -1;
  int epfd = epoll_create1((int)flags);
  if (epfd < 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "epoll_create1: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = (long long)epfd;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_sys_epoll_ctl(long long cap, long long epfd, long long op, long long fd, long long events, long long data) {
  OoResI r;
  oo_cap_require_sys(cap, "sys_epoll_ctl");
  r.ok = 0; r.val = -1;
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = (uint32_t)events;
  ev.data.u64 = (uint64_t)data;
  int rc = epoll_ctl((int)epfd, (int)op, (int)fd, &ev);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "epoll_ctl: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}

OoResS oo_sys_epoll_wait(long long cap, long long epfd, long long max_events, long long timeout_ms) {
  OoResS r;
  oo_cap_require_sys(cap, "sys_epoll_wait");
  r.ok = 0;
  if (max_events <= 0 || max_events > 256) max_events = 64;
  struct epoll_event events[256];
  int n = epoll_wait((int)epfd, events, (int)max_events, (int)timeout_ms);
  if (n < 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "epoll_wait: errno %d", errno);
    r.val = oo_str_lit(errbuf);
    return r;
  }
  if (n == 0) {
    r.ok = 1;
    r.val = oo_str_lit("");
    return r;
  }
  char buf[4096];
  size_t off = 0;
  buf[0] = '\0';
  for (int i = 0; i < n; i++) {
    int written = snprintf(buf + off, sizeof(buf) - off, "%d:%u:%llu\t",
                           events[i].data.fd, events[i].events, (unsigned long long)events[i].data.u64);
    if (written > 0 && (size_t)written < sizeof(buf) - off) {
      off += (size_t)written;
    } else {
      break;
    }
  }
  r.ok = 1;
  r.val = oo_str_lit(buf);
  return r;
}

OoResI oo_sys_close(long long cap, long long fd) {
  OoResI r;
  oo_cap_require_sys(cap, "sys_close");
  r.ok = 0; r.val = -1;
  if (fd < 0) {
    r.err = oo_str_lit("sys_close: invalid fd");
    return r;
  }
  int rc = close((int)fd);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "sys_close: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_sys_timerfd_create(long long cap, long long clockid, long long flags) {
  OoResI r;
  oo_cap_require_sys(cap, "sys_timerfd_create");
  r.ok = 0; r.val = -1;
  int tfd = timerfd_create((int)clockid, (int)flags);
  if (tfd < 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "timerfd_create: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = (long long)tfd;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_sys_timerfd_settime(long long cap, long long tfd, long long flags, long long interval_ns, long long value_ns) {
  OoResI r;
  oo_cap_require_sys(cap, "sys_timerfd_settime");
  r.ok = 0; r.val = -1;
  struct itimerspec its;
  its.it_interval.tv_sec = (time_t)(interval_ns / 1000000000LL);
  its.it_interval.tv_nsec = (long)(interval_ns % 1000000000LL);
  its.it_value.tv_sec = (time_t)(value_ns / 1000000000LL);
  its.it_value.tv_nsec = (long)(value_ns % 1000000000LL);
  int rc = timerfd_settime((int)tfd, (int)flags, &its, NULL);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "timerfd_settime: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_sys_eventfd(long long cap, long long initval, long long flags) {
  OoResI r;
  oo_cap_require_sys(cap, "sys_eventfd");
  r.ok = 0; r.val = -1;
  int efd = eventfd((unsigned int)initval, (int)flags);
  if (efd < 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "eventfd: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = (long long)efd;
  r.err = oo_str_lit("");
  return r;
}
