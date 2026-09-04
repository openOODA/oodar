#include "chs_rt.h"
#include "chs_rt_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>

/* dns_resolve: must return a loopback literal. Path A does not open an
 * unrestricted resolver (which would let getaddrinfo walk /etc/hosts and
 * upstream DNS, defeating the net-floor loopback constraint). */
static int dns_is_loopback_only(const char *h) {
  if (!h || !h[0]) return 0;
  if (strcmp(h, "localhost") == 0) return 1;
  if (strcmp(h, "127.0.0.1") == 0) return 1;
  if (strcmp(h, "::1") == 0) return 1;
  return 0;
}

OoResS oo_dns_resolve(long long cap, OoStr host) {
  oo_cap_require_net(cap, "dns_resolve");
  if (!host.data || host.len <= 0) {
    return (OoResS){0, oo_str_lit("ERR\tdns\tempty host name")};
  }
  char hbuf[256];
  if ((size_t)host.len >= sizeof hbuf) {
    return (OoResS){0, oo_str_lit("ERR\tdns\thost name too long")};
  }
  memcpy(hbuf, host.data, (size_t)host.len);
  hbuf[host.len] = '\0';

  if (dns_is_loopback_only(hbuf)) {
    return (OoResS){1, oo_str_lit("127.0.0.1")};
  }
  return (OoResS){0, oo_str_lit("ERR\tdns\thost not loopback")};
}

OoResS oo_dns_resolve_ipv4(long long cap, OoStr host) {
  oo_cap_require_net(cap, "dns_resolve_ipv4");
  if (!host.data || host.len <= 0) {
    return (OoResS){0, oo_str_lit("ERR\tdns\tempty host name")};
  }
  char hbuf[256];
  if ((size_t)host.len >= sizeof hbuf) {
    return (OoResS){0, oo_str_lit("ERR\tdns\thost name too long")};
  }
  memcpy(hbuf, host.data, (size_t)host.len);
  hbuf[host.len] = '\0';

  if (dns_is_loopback_only(hbuf)) {
    return (OoResS){1, oo_str_lit("127.0.0.1")};
  }
  return (OoResS){0, oo_str_lit("ERR\tdns\thost not loopback")};
}
