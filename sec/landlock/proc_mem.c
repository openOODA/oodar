/* proc_mem.c — Live process memory reader for real-RAM RASP
 *
 * First-principles (Red 8 Byzantine): the user-space cap token alone is
 * insufficient to gate a /proc/self/mem read because the cap token is
 * stored in the SAME memory that /proc/self/mem can read. An attacker
 * who can call oo_proc_mem_read can also read the cap token out of
 * process memory, then forge a call. The defense is to require the
 * kernel-mediated sandbox (Landlock) to be active so that the cap token
 * storage and the read syscall both go through the kernel.
 *
 * Default-deny: oo_proc_mem_read refuses to open /proc/self/mem unless
 * the kernel sandbox is confirmed available. The user-space cap check
 * is a fast-path optimization ON TOP OF the kernel check, not a substitute.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>

#include "../../oodar.h"

extern char *oo_str_alloc_payload(size_t len);

OoResS oo_proc_mem_read(long long cap, long long offset, long long n) {
  OoResS r;
  r.ok = 0;
  r.val = oo_str_lit("");
  if (n <= 0 || n > (1LL << 20)) {
    return r;
  }
  if (offset < 0) {
    return r;
  }
  if (offset > (1LL << 47)) {
    return r;
  }
  /* First-principles gate: refuse to read /proc/self/mem unless the
   * kernel-mediated sandbox (Landlock) is available. This breaks the
   * circular trust between user-space cap storage and the /proc/self/mem
   * reader — an attacker reading process memory cannot forge a Landlock
   * enforcement, only a user-space token. */
  if (!oo_landlock_is_available()) {
    return r;
  }
  oo_cap_require_sys(cap, "proc_mem_read");
  int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return r;
  }
  if (lseek(fd, (off_t)offset, SEEK_SET) == (off_t)-1) {
    close(fd);
    return r;
  }
  char *buf = oo_str_alloc_payload((size_t)n);
  if (!buf) {
    close(fd);
    return r;
  }
  ssize_t got = read(fd, buf, (size_t)n);
  if (got <= 0) {
    buf[0] = '\0';
    OoStr tmp;
    tmp.data = buf;
    tmp.len = 0;
    oo_str_release(tmp);
    close(fd);
    return r;
  }
  buf[got] = '\0';
  r.ok = 1;
  r.val.data = buf;
  r.val.len = got;
  close(fd);
  return r;
}
