/* sys_stdin.c — stdin surface for the LSP stdio loop.
 * oo_read_stdin: one-shot read of all stdin (stdio LSP / pipe).
 * oo_read_stdin_chunk: non-blocking read with a poll(2) timeout, used by
 * the stdio loop to dispatch complete Content-Length or JSON-object frames.
 * Both are FsReadCap-gated (v3.0.0). */
#include "../../oodar.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>

/* Read all stdin (stdio LSP / one-shot). Pipes have no seek. v3.0.0: cap-gated. */
OoStr oo_read_stdin(long long cap) {
  char *buf;
  size_t bcap = 4096;
  size_t n = 0;
  oo_cap_require_fsread(cap, "read_stdin");
  buf = (char *)malloc(bcap);
  if (!buf) return oo_str_lit("");
  for (;;) {
    size_t got;
    if (n + 1024 >= bcap) {
      char *nb;
      bcap *= 2;
      if (bcap > (1u << 20)) {
        free(buf);
        return oo_str_lit("");
      }
      nb = (char *)realloc(buf, bcap);
      if (!nb) {
        free(buf);
        return oo_str_lit("");
      }
      buf = nb;
    }
    got = fread(buf + n, 1, 1024, stdin);
    n += got;
    if (got < 1024) break;
  }
  {
    /* Wrap into a real refcounted OoStr: a raw malloc buffer has no
     * OoStrHeader, so retain/release on it smashes malloc metadata. */
    OoStr r;
    r.data = oo_str_alloc_payload(n);
    memcpy(r.data, buf, n);
    r.len = (long long)n;
    free(buf);
    return r;
  }
}

/* Non-blocking stdin read for the stdio loops.
   Returns Result<String, String>:
     ok=1, val=<chunk> when data is available.
     ok=1, val="" on poll timeout (no data yet; keep polling).
     ok=0 (Err) on EOF, read() failure, or allocation failure.
   v3.0.0: cap-gated.
   v3.0.1: timeout and EOF no longer share ok=0. The LSP loop used to
     break on every idle poll; now only EOF breaks it. */
OoResS oo_read_stdin_chunk(long long cap, long long timeout_ms) {
  struct pollfd pfd;
  oo_cap_require_fsread(cap, "read_stdin_chunk");
  pfd.fd = 0;
  pfd.events = POLLIN;
  int rc = poll(&pfd, 1, (int)timeout_ms);
  if (rc <= 0) {
    OoStr empty = oo_str_lit("");
    OoResS r = { .ok = 1, .val = empty };
    return r;
  }
  if (pfd.revents & (POLLERR | POLLNVAL)) {
    OoStr empty = oo_str_lit("");
    OoResS r = { .ok = 0, .val = empty };
    return r;
  }
  /* POLLIN and/or POLLHUP: attempt the read. A closed writer with
   * buffered bytes still reports POLLHUP, so only a short read proves
   * EOF. A pure timeout never reaches here (rc <= 0 above). */
  if (!(pfd.revents & (POLLIN | POLLHUP))) {
    OoStr empty = oo_str_lit("");
    OoResS r = { .ok = 1, .val = empty };
    return r;
  }
  char *buf = (char *)malloc(4096);
  if (!buf) {
    OoStr empty = oo_str_lit("");
    OoResS r = { .ok = 0, .val = empty };
    return r;
  }
  ssize_t got = read(0, buf, 4096);
  if (got <= 0) {
    free(buf);
    OoStr empty = oo_str_lit("");
    OoResS r = { .ok = 0, .val = empty };
    return r;
  }
  /* Wrap into a real refcounted OoStr: a raw malloc buffer has no
   * OoStrHeader, so retain/release on it smashes malloc metadata. */
  OoStr chunk;
  chunk.data = oo_str_alloc_payload((size_t)got);
  memcpy(chunk.data, buf, (size_t)got);
  chunk.len = (long long)got;
  free(buf);
  OoResS r = { .ok = 1, .val = chunk };
  return r;
}
