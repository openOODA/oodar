/* netfloor_udp.c — UDP ops on top of the netfloor slot table (netfloor.c).
 * Cap tokens: bind_udp uses UdpCap (or BindCap supersede); udp_send/udp_recv
 * use UdpCap. IPv4 loopback only; dotted IPv4 hostnames accepted. */
#include "../../oodar.h"
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

/* slot table (defined in netfloor.c) */
void net_boot(void);
int net_lookup(long long slot, int want_kind);
int net_alloc_slot(int fd, int kind);
OoResS net_err(const char *msg);
OoResS net_ok_fd(int slot);
#define OO_NET_UDP 3

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
