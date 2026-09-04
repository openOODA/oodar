/* M164 TLS product floor: client handshake via system libssl.so.3 (OpenSSL 3).
 * No openssl headers required — local decls + explicit .so.3 link path.
 * When OO_HAVE_OPENSSL is not defined, oo_tls_connect fails closed:
 * no plaintext downgrade, no env-var opt-in, no insecure residual. */
#include "../oodar.h"
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

static OoResS tls_err(const char *msg) {
  OoResS r;
  r.ok = 0;
  r.val = oo_str_lit(msg);
  return r;
}

static int tls_tcp_fd(const char *h, long long port, const char **err) {
  char portstr[16];
  struct addrinfo hints, *res = NULL, *rp;
  int fd = -1;
  *err = "tls_connect: resolve failed";
  if (!h || !h[0] || port < 1 || port > 65535) {
    *err = "tls_connect: bad host/port";
    return -1;
  }
  snprintf(portstr, sizeof portstr, "%lld", (long long)port);
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(h, portstr, &hints, &res) != 0) return -1;
  *err = "tls_connect: connection refused";
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

#if defined(OO_HAVE_OPENSSL)
/* OpenSSL 1.1+/3 C ABI — macros expanded to SSL_ctrl / SSL_CTX_ctrl. */
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
const SSL_METHOD *TLS_client_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
void SSL_CTX_free(SSL_CTX *ctx);
long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void *cb);
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_connect(SSL *ssl);
int SSL_shutdown(SSL *ssl);
long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);

#define TLS1_2_VERSION 0x0303
#define SSL_VERIFY_PEER 0x01
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define SSL_CTRL_SET_MIN_PROTO_VERSION 123
#define SSL_set_tlsext_host_name(s, name) \
  SSL_ctrl((s), SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, (void *)(name))
#define SSL_CTX_set_min_proto_version(ctx, ver) \
  SSL_CTX_ctrl((ctx), SSL_CTRL_SET_MIN_PROTO_VERSION, (ver), NULL)

static OoResS tls_handshake_openssl(int fd, const char *h, long long port) {
  OoResS r;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  char buf[160];
  const SSL_METHOD *meth;
  int rc;
  meth = TLS_client_method();
  if (!meth) {
    close(fd);
    return tls_err("tls_connect: TLS_client_method failed");
  }
  ctx = SSL_CTX_new(meth);
  if (!ctx) {
    close(fd);
    return tls_err("tls_connect: SSL_CTX_new failed");
  }
  (void)SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  (void)SSL_CTX_set_default_verify_paths(ctx);
  ssl = SSL_new(ctx);
  if (!ssl) {
    SSL_CTX_free(ctx);
    close(fd);
    return tls_err("tls_connect: SSL_new failed");
  }
  SSL_set_fd(ssl, fd);
  if (h && h[0]) (void)SSL_set_tlsext_host_name(ssl, h);
  rc = SSL_connect(ssl);
  if (rc != 1) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return tls_err("tls_connect: SSL_connect failed");
  }
  snprintf(buf, sizeof buf, "tls-connected:%s:%lld", h ? h : "", (long long)port);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(fd);
  r.ok = 1;
  r.val = oo_str_lit(buf);
  return r;
}
#endif

OoResS oo_tls_connect(long long cap, OoStr host, long long port) {
  const char *h;
  const char *err = NULL;
  int fd;
  oo_cap_require_tcp(cap, "tls_connect");
  h = host.data ? host.data : "";
  fd = tls_tcp_fd(h, port, &err);
  if (fd < 0) return tls_err(err ? err : "tls_connect: connection refused");

#if defined(OO_HAVE_OPENSSL)
  return tls_handshake_openssl(fd, h, port);
#else
  close(fd);
  return tls_err("tls_connect: OpenSSL not linked (fail closed; no plaintext downgrade)");
#endif
}
