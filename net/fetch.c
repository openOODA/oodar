#include "../oodar.h"
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* R9: real HTTP/1.0 GET via POSIX sockets (http only; https fail-closed). */
OoResS oo_fetch(long long cap, OoStr url) {
  OoResS r;
  const char *u;
  char host[256], path[1024], portstr[12];
  int port = 80, fd = -1, n;
  size_t ulen, i, j;
  struct addrinfo hints, *res = NULL, *rp;
  char req[1400], *body = NULL, *acc = NULL;
  size_t acc_len = 0, acc_cap = 0;
  ssize_t nr;
  oo_cap_require_net(cap, "fetch");
  r.ok = 0;
  r.val = oo_str_lit("fetch failed");
  u = url.data ? url.data : "";
  ulen = url.data ? (size_t)url.len : 0;
  if (ulen >= 8 && strncmp(u, "https://", 8) == 0) {
    r.val = oo_str_lit("https residual: use http:// or external TLS");
    return r;
  }
  if (ulen < 7 || strncmp(u, "http://", 7) != 0) {
    r.val = oo_str_lit("fetch: only http:// URLs supported");
    return r;
  }
  u += 7;
  ulen -= 7;
  i = 0;
  while (i < ulen && u[i] != '/' && u[i] != ':' && i < sizeof(host) - 1) {
    if (u[i] == '\r' || u[i] == '\n' || u[i] == ' ') {
      return r;
    }
    host[i] = u[i];
    i++;
  }
  host[i] = 0;
  if (i == 0) return r;
  if (i < ulen && u[i] == ':') {
    i++;
    j = 0;
    while (i < ulen && u[i] != '/' && j < sizeof(portstr) - 1) {
      portstr[j++] = u[i++];
    }
    portstr[j] = 0;
    port = atoi(portstr);
    if (port <= 0) port = 80;
  }
  if (i < ulen && u[i] == '/') {
    j = 0;
    while (i < ulen && j < sizeof(path) - 1) {
      if (u[i] == '\r' || u[i] == '\n' || u[i] == ' ') {
        return r;
      }
      path[j++] = u[i++];
    }
    path[j] = 0;
  } else {
    path[0] = '/';
    path[1] = 0;
  }
  memset(&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_STREAM;
  snprintf(portstr, sizeof portstr, "%d", port);
  if (getaddrinfo(host, portstr, &hints, &res) != 0) {
    r.val = oo_str_lit("fetch: DNS failed");
    return r;
  }
  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    r.val = oo_str_lit("connection refused");
    return r;
  }
  n = snprintf(req, sizeof req,
               "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
  if (n <= 0 || (size_t)n >= sizeof req) {
    close(fd);
    return r;
  }
  {
    ssize_t nw = 0;
    while (nw < n) {
      ssize_t w = write(fd, req + nw, (size_t)(n - nw));
      if (w <= 0) {
        if (errno == EINTR) continue;
        close(fd);
        return r;
      }
      nw += w;
    }
  }
  acc_cap = 4096;
  acc = (char *)malloc(acc_cap);
  if (!acc) {
    close(fd);
    return r;
  }
  while ((nr = read(fd, req, sizeof req)) > 0) {
    if (acc_len + (size_t)nr + 1 > acc_cap) {
      acc_cap = (acc_len + (size_t)nr + 1) * 2;
      char *nacc = (char *)realloc(acc, acc_cap);
      if (!nacc) {
        free(acc);
        close(fd);
        return r;
      }
      acc = nacc;
    }
    memcpy(acc + acc_len, req, (size_t)nr);
    acc_len += (size_t)nr;
  }
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
