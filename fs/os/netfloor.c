/* M162/M166: real TCP/UDP under NetCap + process-local fd slots (path A).
 * CAP-G1: per-op require_tcp/udp/bind (or NetCap supersede); sock_raw = NetCap only.
 * Breaking: connect/bind keep fds open; Ok("fd:N") not immediate close.
 * SOCK_RAW residual. TLS stays in tls.c (TcpCap|NetCap). */
#include "../../oodar.h"
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define OO_NET_SLOTS 32
#define OO_NET_EMPTY 0
#define OO_NET_TCP 1
#define OO_NET_TCP_LISTEN 2
#define OO_NET_UDP 3

static int g_net_fd[OO_NET_SLOTS];
static int g_net_kind[OO_NET_SLOTS];
static int g_net_inited;
static void net_boot(void) {
  int i;
  if (g_net_inited) return;
  for (i = 0; i < OO_NET_SLOTS; i++) {
    g_net_fd[i] = -1;
    g_net_kind[i] = OO_NET_EMPTY;
  }
  g_net_inited = 1;
}

static OoResS net_err(const char *msg) {
  OoResS r;
  r.ok = 0;
  r.val = oo_str_lit(msg);
  return r;
}

static int net_alloc_slot(int fd, int kind) {
  int i;
  net_boot();
  for (i = 0; i < OO_NET_SLOTS; i++) {
    if (g_net_kind[i] == OO_NET_EMPTY) {
      g_net_fd[i] = fd;
      g_net_kind[i] = kind;
      return i;
    }
  }
  return -1;
}

static int net_lookup(long long slot, int want_kind) {
  int s = (int)slot;
  net_boot();
  if (s < 0 || s >= OO_NET_SLOTS) return -1;
  if (g_net_kind[s] == OO_NET_EMPTY) return -1;
  if (want_kind != 0 && g_net_kind[s] != want_kind) return -2;
  return g_net_fd[s];
}

static OoResS net_ok_fd(int slot) {
  OoResS r;
  char buf[32];
  snprintf(buf, sizeof buf, "fd:%d", slot);
  r.ok = 1;
  r.val = oo_str_lit(buf);
  return r;
}

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

OoResS oo_bind_udp(long long cap, long long port) {
  int fd, slot;
  struct sockaddr_in addr;
  oo_cap_require_udp(cap, "bind_udp");
  if (port < 1 || port > 65535) return net_err("bind_udp: bad port");
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return net_err("bind_udp: socket failed");
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  }
  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) { close(fd); return net_err("bind_udp: bind failed"); }
  slot = net_alloc_slot(fd, OO_NET_UDP);
  if (slot < 0) { close(fd); return net_err("bind_udp: no free slot"); }
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

OoResS oo_udp_send(long long cap, long long slot, OoStr host, long long port, OoStr data) {
  int fd;
  struct sockaddr_in addr;
  ssize_t n;
  const char *h;
  const char *p;
  size_t left;
  oo_cap_require_udp(cap, "udp_send");
  fd = net_lookup(slot, OO_NET_UDP);
  if (fd == -2) return net_err("udp_send: not udp");
  if (fd < 0) return net_err("udp_send: bad slot");
  if (port < 1 || port > 65535) return net_err("udp_send: bad port");
  h = host.data ? host.data : "";
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  if (h[0] && inet_aton(h, &addr.sin_addr) != 0) {
    /* dotted IPv4 */
  } else if (h[0] == 0 || strcmp(h, "localhost") == 0 || strcmp(h, "127.0.0.1") == 0) {
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  } else {
    return net_err("udp_send: host must be IPv4 loopback");
  }
  p = data.data ? data.data : "";
  left = (data.len > 0 && data.len < (1LL << 28)) ? (size_t)data.len : 0;
  n = sendto(fd, p, left, 0, (struct sockaddr *)&addr, sizeof addr);
  if (n < 0 || (size_t)n != left) return net_err("udp_send: failed");
  {
    OoResS r;
    r.ok = 1;
    r.val = oo_str_lit("ok");
    return r;
  }
}

OoResS oo_udp_recv(long long cap, long long slot, long long max_n) {
  int fd;
  ssize_t n;
  char *buf;
  OoResS r;
  size_t want;
  oo_cap_require_udp(cap, "udp_recv");
  fd = net_lookup(slot, OO_NET_UDP);
  if (fd == -2) return net_err("udp_recv: not udp");
  if (fd < 0) return net_err("udp_recv: bad slot");
  if (max_n < 1) return net_err("udp_recv: bad max_n");
  if (max_n > (1LL << 20)) max_n = 1LL << 20;
  want = (size_t)max_n;
  buf = oo_str_alloc_payload(want);
  n = recv(fd, buf, want, 0);
  if (n < 0) {
    oo_payload_free(buf);
    return net_err("udp_recv: failed");
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
/* SOCK_RAW residual: sealed NetCap, always Err (no ambient raw). */
OoResS oo_sock_raw(long long cap, long long proto) {
  (void)proto;
  oo_cap_require_net(cap, "sock_raw");
  return net_err("sock_raw residual: SOCK_RAW not product");
}

