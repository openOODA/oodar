/* qa/tests_stdin_owned_str.c — oo_read_stdin_chunk must return a real
 * refcounted OoStr, not a raw malloc buffer.
 *
 * Regression: sys_stdin.c returned {raw malloc(4096) buffer, len} with no
 * OoStrHeader. Every retain/release on it read/wrote malloc metadata as a
 * refcount (oo_str_release underflows into free(buf-64)), so LSP stdio
 * servers aborted with "double free or corruption" after answering the
 * first frame. The fix wraps the bytes via oo_str_alloc_payload+memcpy.
 *
 * Beats:
 *   1. Pipe a fixed frame into stdin; read one chunk with a granted cap.
 *   2. Assert exact bytes and length.
 *   3. Replay the compiler's retain/release/release pattern, then prove
 *      the heap still works (canary alloc/write/free).
 *
 * Exit codes: 0 — owned string, heap healthy. 1 — defect.
 * Output is fixed text (double-run safe).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../oodar.h"
#include "../types/types_str.h"

static int fails = 0;
#define CHECK(c, msg) do { \
    if (!(c)) { printf("FAIL: %s\n", msg); fails = 1; } \
  } while (0)

int main(void) {
  const char *msg = "Content-Length: 2\r\n\r\n{}";
  size_t mlen = strlen(msg);

  long long cap = oo_cap_grant_fsread();
  /* Timeout on an open pipe with no data: Ok with empty bytes. */
  {
    int idle[2];
    if (pipe(idle) != 0) { printf("FAIL: pipe\n"); return 1; }
    if (dup2(idle[0], 0) < 0) { printf("FAIL: dup2\n"); return 1; }
    close(idle[0]);
    /* Writer stays open: poll must time out, not report EOF. */
    OoResS t = oo_read_stdin_chunk(cap, 50);
    CHECK(t.ok == 1, "timeout must be ok");
    CHECK(t.val.len == 0, "timeout must carry empty bytes");
    close(idle[1]);
  }
  int fds[2];
  if (pipe(fds) != 0) { printf("FAIL: pipe\n"); return 1; }
  if (write(fds[1], msg, mlen) != (ssize_t)mlen) {
    printf("FAIL: pipe write\n");
    return 1;
  }
  close(fds[1]);
  if (dup2(fds[0], 0) < 0) { printf("FAIL: dup2\n"); return 1; }
  close(fds[0]);

  OoResS r = oo_read_stdin_chunk(cap, 1000);
  CHECK(r.ok == 1, "chunk must be ok");
  CHECK(r.val.len == (long long)mlen, "chunk length must match");
  CHECK(r.val.data != NULL, "chunk data must exist");
  if (r.val.data != NULL && r.val.len == (long long)mlen) {
    CHECK(memcmp(r.val.data, msg, mlen) == 0, "chunk bytes must match");
    CHECK(r.val.data[(long long)mlen] == 0, "chunk must be NUL-terminated");
  }
  /* A fresh owned string has exactly one owner and no flags. A raw
   * malloc buffer carries malloc metadata here instead (never rc==1). */
  if (r.val.data != NULL) {
    OoStrHeader *hdr = ((OoStrHeader *)r.val.data) - 1;
    CHECK(hdr->ref_count == 1, "chunk must have exactly one owner");
    CHECK(hdr->flags == 0, "chunk must carry no flags");
  }
  /* Exact compiler pattern from the stdio loop: retain the match extract,
   * then release both the extract and the result value. */
  oo_str_retain(r.val);
  oo_str_release(r.val);
  oo_str_release(r.val);
  /* Heap must still work after the releases. */
  {
    char *canary = (char *)malloc(256);
    CHECK(canary != NULL, "canary alloc must work");
    if (canary != NULL) {
      memset(canary, 0xA5, 256);
      CHECK(canary[0] == (char)0xA5 && canary[255] == (char)0xA5,
            "canary bytes must survive");
      free(canary);
    }
  }
  /* Writer end is closed and bytes were consumed: EOF must be Err. */
  {
    OoResS e = oo_read_stdin_chunk(cap, 50);
    CHECK(e.ok == 0, "EOF must be an error");
  }
  if (fails == 0) printf("PASS: stdin chunk is an owned string\n");
  return fails;
}
