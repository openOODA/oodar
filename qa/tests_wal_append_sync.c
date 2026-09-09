/* qa/tests_wal_append_sync.c — durability primitive for the WAL core build.
 * Beats: cap=0 fail-closed; append preserves prior bytes (no trunc);
 * content exact after fresh re-open; bad dir fails closed (no crash).
 * Double-run via Makefile. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include "../oodar.h"

static int fails = 0;
#define CHECK(cond, tag) do { \
  if (!(cond)) { fprintf(stderr, "FAIL\twal_append_sync\t%s\n", tag); fails++; } \
} while (0)

static int content_eq(OoStr s, const char *want) {
  size_t n = strlen(want);
  if ((size_t)s.len != n) return 0;
  return memcmp(s.data, want, n) == 0;
}

/* cap=0 must fail closed in a child (require exits 1). */
static void w_cap0(void) {
  OoResV r = oo_file_append_sync(0, oo_str_lit("/tmp/ooda_nope.log"), oo_str_lit("x"));
  (void)r;
  _exit(0);
}

static int run_cap0(void) {
  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return 0; }
  if (pid == 0) { alarm(5); w_cap0(); _exit(0); }
  int st = 0;
  waitpid(pid, &st, 0);
  if (WIFEXITED(st) && WEXITSTATUS(st) != 0) return 1;
  if (WIFSIGNALED(st)) return 1;
  return 0;
}

int main(void) {
  setenv("OODA_NO_JAIL", "1", 1);
  CHECK(run_cap0(), "cap=0 must fail closed");
  long long cap = oo_cap_grant_fs();
  char path[256];
  snprintf(path, sizeof path, "/tmp/ooda_write/wal_sync_%d.log", (int)getpid());
  OoStr p = { path, (long long)strlen(path) };
  OoResV w0 = oo_write_file(cap, p, oo_str_lit("BASE\n"));
  CHECK(w0.ok, "seed write_file ok");
  OoResV a1 = oo_file_append_sync(cap, p, oo_str_lit("ONE\n"));
  CHECK(a1.ok, "append ONE ok");
  OoResV a2 = oo_file_append_sync(cap, p, oo_str_lit("TWO\n"));
  CHECK(a2.ok, "append TWO ok");
  /* Fresh re-open: bytes must be exact, prior content preserved. */
  OoResS rd = oo_read_file(cap, p);
  CHECK(rd.ok, "re-read ok");
  if (rd.ok) CHECK(content_eq(rd.val, "BASE\nONE\nTWO\n"), "exact bytes after re-open");
  /* Unwritable parent must fail closed, not crash. */
  OoResV bad = oo_file_append_sync(cap, oo_str_lit("/no/such/dir/x.log"), oo_str_lit("z"));
  CHECK(!bad.ok, "bad dir fails closed");
  unlink(path);
  if (fails == 0) { printf("OK\twal_append_sync\tcap0+append+reopen+badpath\n"); return 0; }
  fprintf(stderr, "FAIL\twal_append_sync\t%d checks\n", fails);
  return 1;
}
