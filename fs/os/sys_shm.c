/* sys_shm.c — POSIX shared memory and mmap operations under SysCap.
 *
 * Implements:
 *   oo_shm_open: shm_open(2) descriptor allocation
 *   oo_shm_unlink: shm_unlink(2) unlinking by name
 *   oo_memfd_create: memfd_create(2) anonymous memory fd
 *   oo_ftruncate: ftruncate(2) resizing
 *   oo_mmap: mmap(2) memory mapping returning "ptr:0x..." token
 *   oo_munmap: munmap(2) unmapping memory buffer
 *   oo_close_fd: close(2) file descriptor cleanup
 *
 * Governed by RULES.oot <= 256 lines and zero ambient authority.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../../oodar.h"
#include "../../oodar_internal.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

OoResI oo_shm_open(long long cap, OoStr name, long long oflag, long long mode) {
  OoResI r;
  oo_cap_require_sys(cap, "shm_open");
  r.ok = 0; r.val = -1;
  const char *n = name.data ? name.data : "";
  if (!n[0] || n[0] != '/') {
    r.err = oo_str_lit("shm_open: name must start with slash");
    return r;
  }
  int fd = shm_open(n, (int)oflag, (mode_t)mode);
  if (fd < 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "shm_open: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = (long long)fd;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_shm_unlink(long long cap, OoStr name) {
  OoResI r;
  oo_cap_require_sys(cap, "shm_unlink");
  r.ok = 0; r.val = -1;
  const char *n = name.data ? name.data : "";
  if (!n[0]) {
    r.err = oo_str_lit("shm_unlink: empty name");
    return r;
  }
  int rc = shm_unlink(n);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "shm_unlink: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_memfd_create(long long cap, OoStr name, long long flags) {
  OoResI r;
  oo_cap_require_sys(cap, "memfd_create");
  r.ok = 0; r.val = -1;
  const char *n = name.data ? name.data : "";
  if (!n[0]) {
    r.err = oo_str_lit("memfd_create: empty name");
    return r;
  }
  int fd = memfd_create(n, (unsigned int)flags);
  if (fd < 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "memfd_create: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = (long long)fd;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_ftruncate(long long cap, long long fd, long long length) {
  OoResI r;
  oo_cap_require_sys(cap, "ftruncate");
  r.ok = 0; r.val = -1;
  if (fd < 0 || length < 0) {
    r.err = oo_str_lit("ftruncate: invalid fd or length");
    return r;
  }
  int rc = ftruncate((int)fd, (off_t)length);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "ftruncate: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}

OoResS oo_mmap(long long cap, long long addr, long long length, long long prot, long long flags, long long fd, long long offset) {
  OoResS r;
  oo_cap_require_sys(cap, "mmap");
  r.ok = 0;
  if (length <= 0) {
    r.val = oo_str_lit("mmap: length must be positive");
    return r;
  }
  void *hint = (void *)(uintptr_t)addr;
  void *ptr = mmap(hint, (size_t)length, (int)prot, (int)flags, (int)fd, (off_t)offset);
  if (ptr == MAP_FAILED) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "mmap: errno %d", errno);
    r.val = oo_str_lit(errbuf);
    return r;
  }
  char ptr_tok[64];
  snprintf(ptr_tok, sizeof(ptr_tok), "ptr:%p", ptr);
  r.ok = 1;
  r.val = oo_str_lit(ptr_tok);
  return r;
}

OoResI oo_munmap(long long cap, OoStr addr_str, long long length) {
  OoResI r;
  oo_cap_require_sys(cap, "munmap");
  r.ok = 0; r.val = -1;
  const char *s = addr_str.data ? addr_str.data : "";
  if (strncmp(s, "ptr:", 4) != 0 || length <= 0) {
    r.err = oo_str_lit("munmap: invalid address token or length");
    return r;
  }
  void *ptr = NULL;
  if (sscanf(s + 4, "%p", &ptr) != 1 || !ptr) {
    r.err = oo_str_lit("munmap: failed to parse address pointer");
    return r;
  }
  int rc = munmap(ptr, (size_t)length);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "munmap: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}

OoResI oo_close_fd(long long cap, long long fd) {
  OoResI r;
  oo_cap_require_sys(cap, "close_fd");
  r.ok = 0; r.val = -1;
  if (fd < 0) {
    r.err = oo_str_lit("close_fd: invalid fd");
    return r;
  }
  int rc = close((int)fd);
  if (rc != 0) {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "close_fd: errno %d", errno);
    r.err = oo_str_lit(errbuf);
    return r;
  }
  r.ok = 1;
  r.val = 0;
  r.err = oo_str_lit("");
  return r;
}
