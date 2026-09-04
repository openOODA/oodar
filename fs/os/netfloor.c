/* M162/M166: real TCP/UDP under NetCap + process-local fd slots (path A).
 * CAP-G1: per-op require_tcp/udp/bind (or NetCap supersede); sock_raw = NetCap only.
 * Breaking: connect/bind keep fds open; Ok("fd:N") not immediate close.
 * SOCK_RAW residual. TLS stays in tls.c (TcpCap|NetCap).
 *
 * This file is the orchestrator: it owns the per-process slot table and
 * the helpers (net_boot/net_alloc_slot/net_lookup/net_err/net_ok_fd) that
 * the TCP and UDP satellite files use. It also implements the SOCK_RAW
 * residual gate. The TCP ops live in netfloor_tcp.c and the UDP ops
 * live in netfloor_udp.c. */
#include "../../oodar.h"
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>

#define OO_NET_SLOTS 32
#define OO_NET_EMPTY 0
#define OO_NET_TCP 1
#define OO_NET_TCP_LISTEN 2
#define OO_NET_UDP 3

int g_net_fd[OO_NET_SLOTS];
int g_net_kind[OO_NET_SLOTS];
int g_net_inited;
static pthread_mutex_t g_net_mu = PTHREAD_MUTEX_INITIALIZER;

void net_boot(void) {
  int i;
  pthread_mutex_lock(&g_net_mu);
  if (g_net_inited) { pthread_mutex_unlock(&g_net_mu); return; }
  for (i = 0; i < OO_NET_SLOTS; i++) {
    g_net_fd[i] = -1;
    g_net_kind[i] = OO_NET_EMPTY;
  }
  g_net_inited = 1;
  pthread_mutex_unlock(&g_net_mu);
}

OoResS net_err(const char *msg) {
  OoResS r;
  r.ok = 0;
  r.val = oo_str_lit(msg);
  return r;
}

int net_alloc_slot(int fd, int kind) {
  int i;
  net_boot();
  pthread_mutex_lock(&g_net_mu);
  for (i = 0; i < OO_NET_SLOTS; i++) {
    if (g_net_kind[i] == OO_NET_EMPTY) {
      g_net_fd[i] = fd;
      g_net_kind[i] = kind;
      pthread_mutex_unlock(&g_net_mu);
      return i;
    }
  }
  pthread_mutex_unlock(&g_net_mu);
  return -1;
}

int net_lookup(long long slot, int want_kind) {
  int s = (int)slot;
  int fd;
  net_boot();
  pthread_mutex_lock(&g_net_mu);
  if (s < 0 || s >= OO_NET_SLOTS) { pthread_mutex_unlock(&g_net_mu); return -1; }
  if (g_net_kind[s] == OO_NET_EMPTY) { pthread_mutex_unlock(&g_net_mu); return -1; }
  if (want_kind != 0 && g_net_kind[s] != want_kind) {
    pthread_mutex_unlock(&g_net_mu);
    return -2;
  }
  fd = g_net_fd[s];
  pthread_mutex_unlock(&g_net_mu);
  return fd;
}

OoResS net_ok_fd(int slot) {
  OoResS r;
  char buf[32];
  snprintf(buf, sizeof buf, "fd:%d", slot);
  r.ok = 1;
  r.val = oo_str_lit(buf);
  return r;
}

/* SOCK_RAW residual: sealed NetCap, always Err (no ambient raw). */
OoResS oo_sock_raw(long long cap, long long proto) {
  (void)proto;
  oo_cap_require_net(cap, "sock_raw");
  return net_err("sock_raw residual: SOCK_RAW not product");
}
