#ifndef OODAR_SYS_SHM_H
#define OODAR_SYS_SHM_H

#include "../../types.h"

OoResI oo_shm_open(long long cap, OoStr name, long long oflag, long long mode);
OoResI oo_shm_unlink(long long cap, OoStr name);
OoResI oo_memfd_create(long long cap, OoStr name, long long flags);
OoResI oo_ftruncate(long long cap, long long fd, long long length);
OoResS oo_mmap(long long cap, long long addr_hint, long long length, long long prot, long long flags, long long fd, long long offset);
OoResI oo_munmap(long long cap, OoStr ptr_token, long long length);
OoResI oo_close_fd(long long cap, long long fd);

#endif
