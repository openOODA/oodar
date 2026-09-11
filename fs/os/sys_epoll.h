#ifndef OODAR_SYS_EPOLL_H
#define OODAR_SYS_EPOLL_H

#include "../../types.h"

OoResI oo_sys_epoll_create1(long long cap, long long flags);
OoResI oo_sys_epoll_ctl(long long cap, long long epfd, long long op, long long fd, long long events, long long data);
OoResS oo_sys_epoll_wait(long long cap, long long epfd, long long max_events, long long timeout_ms);
OoResI oo_sys_close(long long cap, long long fd);
OoResI oo_sys_timerfd_create(long long cap, long long clockid, long long flags);
OoResI oo_sys_timerfd_settime(long long cap, long long tfd, long long flags, long long interval_ns, long long value_ns);
OoResI oo_sys_eventfd(long long cap, long long initval, long long flags);

#endif
