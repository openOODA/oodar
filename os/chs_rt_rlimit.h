#ifndef CHS_RT_RLIMIT_H
#define CHS_RT_RLIMIT_H
#include "chs_rt.h"

OoResS oo_rlimit_set_mem_mb(long long cap, long long megabytes);
OoResS oo_rlimit_set_nofile(long long cap, long long max_fds);
OoResS oo_rlimit_set_cpu_sec(long long cap, long long seconds);

#endif
