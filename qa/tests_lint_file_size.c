/* qa/tests_lint_file_size.c — every .c and .h must be ≤ 256 lines.
 *
 * Per RULES.oot §1.21 and the v2.3.0 file-split goal, every source
 * file in the umbrella must be ≤ 256 lines so smaller-context LLMs
 * (8K-32K tokens) can hold an entire file in their context window
 * and reason about type signatures, function bodies, and includes
 * without fragmenting across multiple reads.
 *
 * v3.1.2 added: this CI lint, after the v2.3.0 file split landed
 * 60+ files across 9 new sub-dirs and the v3.1.0 audit further
 * trimmed arena.c, gpu_launch.c, and pq_aead.c. Two algorithm-
 * internal files (mldsa_internal.c, mlkem_internal.c) are
 * documented exceptions — the FIPS 203/204 NTT + sampling +
 * polynomial arithmetic are tightly coupled and splitting them
 * would fragment the algorithm without a functional boundary.
 *
 * Exit codes:
 *   0 — every file ≤ 256 lines (excluding documented exceptions)
 *   1 — files over 256 lines; lists the offenders
 *   2 — cannot read directory tree
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

/* Documented algorithm-internal exceptions. The cap exists to help
 * smaller LLMs; the FIPS 203/204 NTT internals are densely coupled
 * and a single-file read is more useful than 4 fragmented files.
 * Add to this list only with a CHANGES.md note. Paths may be
 * relative to the repo root, with or without a leading "./". */
static const char *EXCEPTIONS[] = {
  "sec/pqc/mldsa/mldsa_internal.c",
  "sec/pqc/mlkem/mlkem_internal.c",
  NULL,
};

static int is_exception(const char *path) {
  /* strip leading "./" or any absolute-path prefix to get the repo-relative
   * form. EXCEPTIONS lists paths like "sec/pqc/mldsa/mldsa_internal.c";
   * the scanner sees the absolute path from OODAR_REPO. */
  const char *suffix = strstr(path, "sec/pqc/");
  if (!suffix) {
    const char *p = path;
    if (p[0] == '.' && p[1] == '/') p += 2;
    suffix = p;
  }
  for (int i = 0; EXCEPTIONS[i]; i++) {
    if (strcmp(suffix, EXCEPTIONS[i]) == 0) return 1;
  }
  return 0;
}

static int is_source_file(const char *name) {
  size_t n = strlen(name);
  if (n < 3) return 0;
  const char *dot = strrchr(name, '.');
  if (!dot) return 0;
  return strcmp(dot, ".c") == 0 || strcmp(dot, ".h") == 0;
}

static int line_count(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  int n = 0;
  int c;
  while ((c = fgetc(f)) != EOF) if (c == '\n') n++;
  fclose(f);
  return n;
}

static int scan(const char *dir, FILE *report) {
  DIR *d = opendir(dir);
  if (!d) return 0;
  struct dirent *e;
  int ok = 1;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') {
      /* skip . and .. but not .git contents (we don't recurse into .git) */
      if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
      if (strcmp(e->d_name, ".git") == 0) continue;
    }
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
    struct stat st;
    if (stat(path, &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) {
      if (!scan(path, report)) ok = 0;
    } else if (is_source_file(e->d_name)) {
      int n = line_count(path);
      if (n > 256 && !is_exception(path)) {
        fprintf(report, "OVER: %s (%d lines)\n", path, n);
        ok = 0;
      }
    }
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
    printf("OK\tlint\tall .c/.h files ≤ 256 lines (2 algorithm-internal exceptions documented)\n");
    return 0;
  }
  fprintf(stderr, "FAIL\tlint\tfiles over 256 lines:\n%s", buf);
  fprintf(stderr, "\tSplit per the v2.3.0 file-split convention. Add to EXCEPTIONS only with a CHANGES.md note.\n");
  return 1;
}
