/* netfloor_tcp.c — TCP ops on top of the netfloor slot table (netfloor.c).
 * Cap tokens: bind uses BindCap; connect/accept/write/read/close use TcpCap.
 * SOCK_STREAM loopback only; no out-of-loopback connect. */
#include "../../oodar.h"
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
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
#define OO_NET_TCP 1
#define OO_NET_TCP_LISTEN 2

OoResS oo_tcp_bind(long long cap, long long port) {
  int fd, slot;
  struct sockaddr_in addr;
  oo_cap_require_bind(cap, "tcp_bind");
  if (port < 1 || port > 65535) return net_err("tcp_bind: bad port");
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return net_err("tcp_bind: socket failed");
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  }
  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) { close(fd); return net_err("tcp_bind: bind failed"); }
  if (listen(fd, 1) != 0) { close(fd); return net_err("tcp_bind: listen failed"); }
  slot = net_alloc_slot(fd, OO_NET_TCP_LISTEN);
  if (slot < 0) { close(fd); return net_err("tcp_bind: no free slot"); }
  return net_ok_fd(slot);
}

/* G1 fix: accept one connection from a listening slot. */
OoResS oo_tcp_accept(long long cap, long long listen_slot) {
  int lfd, afd, slot;
  struct sockaddr_in addr;
  socklen_t alen = sizeof addr;
  oo_cap_require_tcp(cap, "tcp_accept");
  lfd = net_lookup(listen_slot, OO_NET_TCP_LISTEN);
  if (lfd == -2) return net_err("tcp_accept: not a listen slot");
  if (lfd < 0) return net_err("tcp_accept: bad listen slot");
  afd = accept(lfd, (struct sockaddr *)&addr, &alen);
  if (afd < 0) return net_err("tcp_accept: accept failed");
  slot = net_alloc_slot(afd, OO_NET_TCP);
  if (slot < 0) { close(afd); return net_err("tcp_accept: no free slot"); }
  return net_ok_fd(slot);
}

OoResS oo_tcp_connect(long long cap, OoStr host, long long port) {
  char portstr[16];
  struct addrinfo hints, *res = NULL, *rp;
  int fd = -1, slot;
  const char *h;
  oo_cap_require_tcp(cap, "tcp_connect");
  h = host.data ? host.data : "";
  if (!h[0] || port < 1 || port > 65535) return net_err("tcp_connect: bad host/port");
  snprintf(portstr, sizeof portstr, "%lld", (long long)port);
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(h, portstr, &hints, &res) != 0) return net_err("tcp_connect: resolve failed");
  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return net_err("tcp_connect: connection refused");
  slot = net_alloc_slot(fd, OO_NET_TCP);
  if (slot < 0) { close(fd); return net_err("tcp_connect: no free slot"); }
  return net_ok_fd(slot);
}

OoResS oo_tcp_write(long long cap, long long slot, OoStr data) {
  int fd;
  ssize_t n;
  const char *p;
  size_t left;
  oo_cap_require_tcp(cap, "tcp_write");
  fd = net_lookup(slot, OO_NET_TCP);
  if (fd == -2) return net_err("tcp_write: not connected tcp");
  if (fd < 0) return net_err("tcp_write: bad slot");
  p = data.data ? data.data : "";
  left = (data.len > 0 && data.len < (1LL << 28)) ? (size_t)data.len : 0;
  while (left > 0) {
    n = write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) continue;
      return net_err("tcp_write: failed");
    }
    if (n == 0) return net_err("tcp_write: short");
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

OoResS oo_tcp_read(long long cap, long long slot, long long max_n) {
  int fd;
  ssize_t n;
  char *buf;
  OoResS r;
  size_t want;
  oo_cap_require_tcp(cap, "tcp_read");
  fd = net_lookup(slot, OO_NET_TCP);
  if (fd == -2) return net_err("tcp_read: not connected tcp");
  if (fd < 0) return net_err("tcp_read: bad slot");
  if (max_n < 1) return net_err("tcp_read: bad max_n");
  if (max_n > (1LL << 20)) max_n = 1LL << 20;
  want = (size_t)max_n;
  buf = oo_str_alloc_payload(want);
  n = read(fd, buf, want);
  if (n < 0) {
    oo_payload_free(buf);
    return net_err("tcp_read: failed");
  }
  r.ok = 1;
  r.val.len = n;
  r.val.data = buf;
  if ((size_t)n < want) buf[n] = 0;
  return r;
}

OoResS oo_tcp_close(long long cap, long long slot) {
  int s = (int)slot;
  OoResS r;
  oo_cap_require_tcp(cap, "tcp_close");
  net_boot();
  if (s < 0 || s >= OO_NET_SLOTS || g_net_kind[s] == OO_NET_EMPTY)
    return net_err("tcp_close: bad slot");
  close(g_net_fd[s]);
  g_net_fd[s] = -1;
  g_net_kind[s] = OO_NET_EMPTY;
  r.ok = 1;
  r.val = oo_str_lit("closed");
  return r;
}
