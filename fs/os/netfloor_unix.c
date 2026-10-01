/* netfloor_unix.c — AF_UNIX stream ops on the shared netfloor slot table.
 *
 * Cap tokens: bind takes BindCap plus FsWriteCap, because binding materialises a
 * filesystem node; accept/connect/read/write/close take FsCap. FsWriteCap is also
 * required to unlink a socket path, since the socket file is real state.
 *
 * Every descriptor is opened SOCK_CLOEXEC so a child process can never inherit
 * a listener or a live connection. Bound sockets are chmod 0600 so only the
 * owning user can reach the control plane. Stale socket files are unlinked
 * before bind so a crashed predecessor does not wedge startup. */
#include "../../oodar.h"
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>

/* slot table (defined in netfloor.c) */
void net_boot(void);
int net_lookup(long long slot, int want_kind);
int net_alloc_slot(int fd, int kind);
OoResS net_err(const char *msg);
OoResS net_ok_fd(int slot);
extern int g_net_fd[32];
extern int g_net_kind[32];
#define OO_NET_SLOTS 32
#define OO_NET_EMPTY 0
#define OO_NET_UNIX_LISTEN 3
#define OO_NET_UNIX 4

/* Fill a sockaddr_un from a path, rejecting anything that cannot be stored. */
static int unix_addr(struct sockaddr_un *sa, OoStr path) {
  const char *p;
  size_t n;
  memset(sa, 0, sizeof *sa);
  sa->sun_family = AF_UNIX;
  p = path.data ? path.data : "";
  n = (path.len > 0) ? (size_t)path.len : strlen(p);
  if (n == 0) return -1;
  if (n >= sizeof sa->sun_path) return -2; /* sun_path has no room for a terminator */
  memcpy(sa->sun_path, p, n);
  sa->sun_path[n] = 0;
  return 0;
}

static void unix_drop(int slot) {
  net_boot();
  if (slot < 0 || slot >= OO_NET_SLOTS) return;
  if (g_net_fd[slot] >= 0) close(g_net_fd[slot]);
  g_net_fd[slot] = -1;
  g_net_kind[slot] = OO_NET_EMPTY;
}

OoResS oo_unix_unlink(long long fsw_cap, OoStr path) {
  const char *p;
  oo_cap_require_fswrite(fsw_cap, "unix_unlink");
  p = path.data ? path.data : "";
  if (!p[0] || path.len >= 4096) return net_err("unix_unlink: bad path");
  if (unlink(p) != 0 && errno != ENOENT) return net_err("unix_unlink: failed");
  {
    OoResS r;
    r.ok = 1;
    r.val = oo_str_lit("unlinked");
    return r;
  }
}

OoResS oo_unix_bind(long long bind_cap, long long fsw_cap, OoStr path) {
  struct sockaddr_un sa;
  int fd, slot, arc;
  oo_cap_require_bind(bind_cap, "unix_bind");
  oo_cap_require_fswrite(fsw_cap, "unix_bind");
  arc = unix_addr(&sa, path);
  if (arc == -1) return net_err("unix_bind: empty path");
  if (arc == -2) return net_err("unix_bind: path too long for sun_path");
  /* A leftover socket file from a crashed predecessor would make bind fail. */
  if (unlink(sa.sun_path) != 0 && errno != ENOENT)
    return net_err("unix_bind: stale socket not removable");
  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return net_err("unix_bind: socket failed");
  if (bind(fd, (struct sockaddr *)&sa, (socklen_t)sizeof sa) != 0) {
    close(fd);
    return net_err("unix_bind: bind failed");
  }
  if (chmod(sa.sun_path, 0600) != 0) {
    close(fd);
    unlink(sa.sun_path);
    return net_err("unix_bind: chmod failed");
  }
  if (listen(fd, 16) != 0) {
    close(fd);
    unlink(sa.sun_path);
    return net_err("unix_bind: listen failed");
  }
  slot = net_alloc_slot(fd, OO_NET_UNIX_LISTEN);
  if (slot < 0) {
    close(fd);
    unlink(sa.sun_path);
    return net_err("unix_bind: no free slot");
  }
  return net_ok_fd(slot);
}

OoResS oo_unix_accept(long long fs_cap, long long listen_slot) {
  int lfd, afd, slot;
  oo_cap_require_fs(fs_cap, "unix_accept");
  lfd = net_lookup((int)listen_slot, OO_NET_UNIX_LISTEN);
  if (lfd == -2) return net_err("unix_accept: not a unix listen slot");
  if (lfd < 0) return net_err("unix_accept: bad listen slot");
  afd = accept(lfd, NULL, NULL);
  if (afd < 0) {
    if (errno == EINTR) return net_err("unix_accept: interrupted");
    return net_err("unix_accept: accept failed");
  }
  {
    int flags = fcntl(afd, F_GETFD, 0);
    if (flags >= 0) fcntl(afd, F_SETFD, flags | FD_CLOEXEC);
  }
  slot = net_alloc_slot(afd, OO_NET_UNIX);
  if (slot < 0) {
    close(afd);
    return net_err("unix_accept: no free slot");
  }
  return net_ok_fd(slot);
}

OoResS oo_unix_connect(long long fs_cap, long long fsw_cap, OoStr path) {
  struct sockaddr_un sa;
  int fd, slot, arc;
  oo_cap_require_fs(fs_cap, "unix_connect");
  oo_cap_require_fswrite(fsw_cap, "unix_connect");
  arc = unix_addr(&sa, path);
  if (arc == -1) return net_err("unix_connect: empty path");
  if (arc == -2) return net_err("unix_connect: path too long for sun_path");
  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return net_err("unix_connect: socket failed");
  if (connect(fd, (struct sockaddr *)&sa, (socklen_t)sizeof sa) != 0) {
    close(fd);
    return net_err("unix_connect: no listener");
  }
  slot = net_alloc_slot(fd, OO_NET_UNIX);
  if (slot < 0) {
    close(fd);
    return net_err("unix_connect: no free slot");
  }
  return net_ok_fd(slot);
}

OoResS oo_unix_write(long long fs_cap, long long slot, OoStr data) {
  int fd;
  ssize_t n;
  const char *p;
  size_t left;
  oo_cap_require_fs(fs_cap, "unix_write");
  fd = net_lookup((int)slot, OO_NET_UNIX);
  if (fd == -2) return net_err("unix_write: not a unix connection");
  if (fd < 0) return net_err("unix_write: bad slot");
  p = data.data ? data.data : "";
  left = (data.len > 0 && data.len < (1LL << 28)) ? (size_t)data.len : 0;
  while (left > 0) {
    n = write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) continue;
      return net_err("unix_write: failed");
    }
    if (n == 0) return net_err("unix_write: short");
    p += (size_t)n;
    left -= (size_t)n;
  }
  {
    OoResS r;
    r.ok = 1;
    r.val = oo_str_lit("ok");
    return r;
  }
}

OoResS oo_unix_read(long long fs_cap, long long slot, long long max_n) {
  int fd;
  ssize_t n;
  char *buf;
  OoResS r;
  size_t want;
  oo_cap_require_fs(fs_cap, "unix_read");
  fd = net_lookup((int)slot, OO_NET_UNIX);
  if (fd == -2) return net_err("unix_read: not a unix connection");
  if (fd < 0) return net_err("unix_read: bad slot");
  if (max_n < 1) return net_err("unix_read: bad max_n");
  if (max_n > (1LL << 20)) max_n = 1LL << 20;
  want = (size_t)max_n;
  buf = oo_str_alloc_payload(want);
  n = read(fd, buf, want);
  if (n < 0) {
    oo_payload_free(buf);
    if (errno == EINTR) return net_err("unix_read: interrupted");
    return net_err("unix_read: failed");
  }
  r.ok = 1;
  r.val.len = n;
  r.val.data = buf;
  if ((size_t)n < want) buf[n] = 0;
  return r;
}

/* Bounded read for frame assembly.
   Mirrors oo_read_stdin_chunk: a stream socket carries no message boundaries,
   so a reader that wants exactly one frame cannot use a bare blocking read --
   a peer whose frame arrives in pieces would leave the loop parked in read(2)
   forever. poll(2) first, then read, and report the three cases apart:
     ok=1, val=<chunk>  data was available
     ok=1, val=""       the timeout elapsed; call again to keep waiting
     ok=0 (Err)         peer closed, poll error, or allocation failure
   A short read is not EOF: the caller decides what a complete frame is. */
OoResS oo_unix_read_timeout(long long fs_cap, long long slot, long long timeout_ms, long long max_n) {
  struct pollfd pfd;
  int fd, rc;
  ssize_t n;
  char *buf;
  size_t want;
  OoResS r;
  oo_cap_require_fs(fs_cap, "unix_read_timeout");
  fd = net_lookup((int)slot, OO_NET_UNIX);
  if (fd == -2) return net_err("unix_read_timeout: not a unix connection");
  if (fd < 0) return net_err("unix_read_timeout: bad slot");
  if (max_n < 1) max_n = 1LL << 16;
  if (max_n > (1LL << 20)) max_n = 1LL << 20;
  if (timeout_ms < 0) timeout_ms = 0;
  if (timeout_ms > 3600000) timeout_ms = 3600000;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  rc = poll(&pfd, 1, (int)timeout_ms);
  if (rc < 0) {
    if (errno == EINTR) { r.ok = 1; r.val = oo_str_lit(""); return r; }
    return net_err("unix_read_timeout: poll failed");
  }
  if (rc == 0) { r.ok = 1; r.val = oo_str_lit(""); return r; }
  if (pfd.revents & (POLLERR | POLLNVAL)) return net_err("unix_read_timeout: poll error");
  /* POLLIN and/or POLLHUP: attempt the read. A hung-up peer can still have
     buffered bytes queued, so only a zero-length read proves EOF. */
  if (!(pfd.revents & (POLLIN | POLLHUP))) { r.ok = 1; r.val = oo_str_lit(""); return r; }
  want = (size_t)max_n;
  buf = oo_str_alloc_payload(want);
  if (!buf) return net_err("unix_read_timeout: out of memory");
  n = read(fd, buf, want);
  if (n < 0) {
    oo_payload_free(buf);
    if (errno == EINTR) { r.ok = 1; r.val = oo_str_lit(""); return r; }
    return net_err("unix_read_timeout: failed");
  }
  if (n == 0) {
    oo_payload_free(buf);
    return net_err("unix_read_timeout: eof");
  }
  r.ok = 1;
  r.val.len = (long long)n;
  r.val.data = buf;
  if ((size_t)n < want) buf[n] = 0;
  return r;
}

OoResS oo_unix_close(long long fs_cap, long long slot) {
  int s = (int)slot;
  OoResS r;
  oo_cap_require_fs(fs_cap, "unix_close");
  net_boot();
  if (s < 0 || s >= OO_NET_SLOTS || g_net_kind[s] == OO_NET_EMPTY)
    return net_err("unix_close: bad slot");
  unix_drop(s);
  r.ok = 1;
  r.val = oo_str_lit("closed");
  return r;
}
