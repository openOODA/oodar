/* qa/tests_lint_anchors.c — every directory must have ANCHOR.oo.
 *
 * Walks the repo and verifies that every leaf-and-intermediate directory
 * (excluding the v2.3.0-known exception list below) has an ANCHOR.oo
 * file at its root. The ANCHOR.oo is the Academy 4-Element Header
 * convention (NORTHSTAR.oot Pillar 4) that documents the directory's
 * logline + beats in a way smaller LLMs can read before opening the
 * .c files.
 *
 * v3.1.2 added: this CI lint, after the v2.3.0 file split left 8
 * new sub-dirs without ANCHOR.oo (caught by the round-4 zero-trust
 * audit) and v3.1.0 had to manually write 9 ANCHOR.oo files.
 *
 * Exit codes:
 *   0 — every required directory has ANCHOR.oo
 *   1 — missing ANCHOR.oo; lists the offenders
 *   2 — cannot read directory tree
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

/* Directories that legitimately do NOT have ANCHOR.oo. Be careful
 * adding to this list — the goal is to converge to zero entries. */
static const char *EXCLUDE[] = {
  ".git",
  "scripts",     /* build scripts, not domain code */
  "qa",          /* tests, not domain code */
  "build",       /* build artifacts */
  "lib",         /* build artifacts */
  "examples",    /* examples are docs, not domain code */
  "docs",        /* .oot docs, not domain code */
  "node_modules",
  ".github",
  NULL,
};

static int is_excluded(const char *name) {
  for (int i = 0; EXCLUDE[i]; i++) {
    if (strcmp(name, EXCLUDE[i]) == 0) return 1;
  }
  return 0;
}

static int has_anchor(const char *dir) {
  char path[1024];
  snprintf(path, sizeof path, "%s/ANCHOR.oo", dir);
  struct stat st;
  return stat(path, &st) == 0;
}

static int is_dir(const char *path) {
  struct stat st;
  if (stat(path, &st) != 0) return 0;
  return S_ISDIR(st.st_mode);
}

static int scan(const char *dir, FILE *report) {
  DIR *d = opendir(dir);
  if (!d) return 0;
  struct dirent *e;
  int ok = 1;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') continue;
    if (is_excluded(e->d_name)) continue;
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
    if (!is_dir(path)) continue;
    if (!has_anchor(path)) {
      fprintf(report, "MISSING: %s\n", path);
      ok = 0;
    }
    if (!scan(path, report)) ok = 0;
  }
  closedir(d);
  return ok;
}

int main(void) {
  const char *root = getenv("OODAR_REPO");
  if (!root) root = ".";

  FILE *report = tmpfile();
  if (!report) { fprintf(stderr, "ERR\tlint\ttmpfile failed\n"); return 2; }

  int ok = scan(root, report);

  rewind(report);
  char buf[1 << 14];
  size_t n = fread(buf, 1, sizeof buf - 1, report);
  buf[n] = 0;
  fclose(report);

  if (ok) {
    printf("OK\tlint\tall directories have ANCHOR.oo\n");
    return 0;
  }
  fprintf(stderr, "FAIL\tlint\tmissing ANCHOR.oo:\n%s", buf);
  fprintf(stderr, "\tAdd a 4-element header (Title, Logline, Setup, Beats) to each missing dir.\n");
  return 1;
}
