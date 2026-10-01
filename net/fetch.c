#include "../oodar.h"
#include "../oodar_internal.h"
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int fetch_parse_url(const char *u, size_t ulen, int *is_https, char *host, size_t host_sz, int *port, char *path, size_t path_sz) {
  size_t i, j;
  char portstr[12];
  if (ulen >= 8 && strncmp(u, "https://", 8) == 0) {
    *is_https = 1; *port = 443; u += 8; ulen -= 8;
  } else if (ulen >= 7 && strncmp(u, "http://", 7) == 0) {
    *is_https = 0; *port = 80; u += 7; ulen -= 7;
  } else {
    return -1;
  }
  i = 0;
  while (i < ulen && u[i] != '/' && u[i] != ':' && i < host_sz - 1) {
    if (u[i] == '\r' || u[i] == '\n' || u[i] == ' ') return -1;
    host[i] = u[i];
    i++;
  }
  host[i] = 0;
  if (i == 0) return -1;
  if (i < ulen && u[i] == ':') {
    i++; j = 0;
    while (i < ulen && u[i] != '/' && j < sizeof(portstr) - 1) {
      portstr[j++] = u[i++];
    }
    portstr[j] = 0;
    *port = atoi(portstr);
    if (*port <= 0) *port = *is_https ? 443 : 80;
  }
  if (i < ulen && u[i] == '/') {
    j = 0;
    while (i < ulen && j < path_sz - 1) {
      if (u[i] == '\r' || u[i] == '\n' || u[i] == ' ') return -1;
      path[j++] = u[i++];
    }
    path[j] = 0;
  } else {
    path[0] = '/'; path[1] = 0;
  }
  return 0;
}

static int fetch_tcp_connect(const char *host, int port) {
  char portstr[12];
  struct addrinfo hints, *res = NULL, *rp;
  int fd = -1;
  memset(&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_STREAM;
  snprintf(portstr, sizeof portstr, "%d", port);
  if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

static int fetch_send_all(int fd, void *tls_sess, const char *req, int n) {
  ssize_t nw = 0;
  while (nw < n) {
    ssize_t w = tls_sess ? oo_tls_write(tls_sess, req + nw, (size_t)(n - nw))
                         : write(fd, req + nw, (size_t)(n - nw));
    if (w <= 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    nw += w;
  }
  return 0;
}

OoResS oo_fetch(long long cap, OoStr url) {
  OoResS r;
  const char *u;
  char host[256], path[1024], req[1400], *body = NULL, *acc = NULL;
  int port = 80, is_https = 0, fd = -1, n;
  size_t ulen, acc_len = 0, acc_cap = 0;
  ssize_t nr;
  void *tls_sess = NULL;

  oo_cap_require_net(cap, "fetch");
  r.ok = 0;
  r.val = oo_str_lit("fetch failed");
  u = url.data ? url.data : "";
  ulen = url.data ? (size_t)url.len : 0;
  if (fetch_parse_url(u, ulen, &is_https, host, sizeof host, &port, path, sizeof path) != 0) {
    r.val = oo_str_lit("fetch: URL parse failed or unsupported scheme");
    return r;
  }
  fd = fetch_tcp_connect(host, port);
  if (fd < 0) {
    r.val = oo_str_lit("connection refused");
    return r;
  }
  if (is_https) {
    tls_sess = oo_tls_connect_fd(fd, host);
    if (!tls_sess) {
      close(fd);
      r.val = oo_str_lit("fetch: TLS handshake failed");
      return r;
    }
  }
  n = snprintf(req, sizeof req, "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
  if (n <= 0 || (size_t)n >= sizeof req || fetch_send_all(fd, tls_sess, req, n) != 0) {
    if (tls_sess) oo_tls_close(tls_sess);
    close(fd);
    return r;
  }
  acc_cap = 4096;
  acc = (char *)malloc(acc_cap);
  if (!acc) {
    if (tls_sess) oo_tls_close(tls_sess);
    close(fd);
    return r;
  }
  while ((nr = tls_sess ? oo_tls_read(tls_sess, req, sizeof req) : read(fd, req, sizeof req)) > 0) {
    if (acc_len + (size_t)nr + 1 > acc_cap) {
      acc_cap = (acc_len + (size_t)nr + 1) * 2;
      char *nacc = (char *)realloc(acc, acc_cap);
      if (!nacc) {
        free(acc);
        if (tls_sess) oo_tls_close(tls_sess);
        close(fd);
        return r;
      }
      acc = nacc;
    }
    memcpy(acc + acc_len, req, (size_t)nr);
    acc_len += (size_t)nr;
  }
  if (tls_sess) oo_tls_close(tls_sess);
  close(fd);
  acc[acc_len] = 0;
  body = strstr(acc, "\r\n\r\n");
  if (!body) {
    free(acc);
    r.val = oo_str_lit("fetch: bad response");
    return r;
  }
  body += 4;
  {
    size_t blen = acc_len - (size_t)(body - acc);
    char *out = oo_str_alloc_payload(blen);
    memcpy(out, body, blen);
    free(acc);
    r.ok = 1;
    r.val.data = out;
    r.val.len = (long long)blen;
  }
  return r;
}
