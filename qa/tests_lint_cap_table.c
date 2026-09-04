/* qa/tests_lint_cap_table.c — caps.h is truth; json must match C symbols.
 * No python. Parses #define OODAR_CAP_* from caps.h and require names
 * from cap_table.json. Require must appear in caps.h. Grantee paths
 * that look like files must exist on disk. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int fail;

static char *slurp(const char *path) {
  FILE *f = fopen(path, "r");
  char *b;
  long n;
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n < 0 || n > (1L << 20)) { fclose(f); return NULL; }
  b = (char *)malloc((size_t)n + 1);
  if (!b) { fclose(f); return NULL; }
  if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
  b[n] = 0;
  fclose(f);
  return b;
}

int main(void) {
  const char *root = getenv("OODAR_REPO");
  char hp[512], jp[512];
  char *h, *j, *p;
  if (!root) root = ".";
  snprintf(hp, sizeof hp, "%s/sec/cap/caps.h", root);
  snprintf(jp, sizeof jp, "%s/sec/cap/cap_table.json", root);
  h = slurp(hp);
  j = slurp(jp);
  if (!h || !j) {
    fprintf(stderr, "FAIL\tlint\tcannot read caps.h or cap_table.json\n");
    return 2;
  }
  p = h;
  while ((p = strstr(p, "#define OODAR_CAP_")) != NULL) {
    char name[64];
    int i = 0;
    p += 18;
    while (p[i] && p[i] != ' ' && p[i] != '\t' && i < 63) {
      name[i] = p[i];
      i++;
    }
    name[i] = 0;
    if (!strstr(j, name)) {
      fprintf(stderr, "FAIL\tlint\tOODAR_CAP_%s missing from cap_table.json\n", name);
      fail = 1;
    }
    p += i;
  }
  p = j;
  while ((p = strstr(p, "\"require\"")) != NULL) {
    char req[80];
    int i = 0;
    const char *q = strchr(p, ':');
    if (!q) break;
    q++;
    while (*q == ' ' || *q == '\t' || *q == '"') q++;
    if (q[0] == '(') { p = q; continue; }
    while (q[i] && q[i] != '"' && i < 79) { req[i] = q[i]; i++; }
    req[i] = 0;
    if (req[0] && !strstr(h, req)) {
      fprintf(stderr, "FAIL\tlint\trequire %s not in caps.h\n", req);
      fail = 1;
    }
    p = q + i;
  }
  p = j;
  while ((p = strstr(p, "\"grantee\"")) != NULL) {
    char g[256];
    int i = 0;
    const char *q = strchr(p, ':');
    char *comma;
    if (!q) break;
    q++;
    while (*q == ' ' || *q == '\t' || *q == '"') q++;
    if (q[0] == '(') { p = q; continue; }
    while (q[i] && q[i] != '"' && i < 255) { g[i] = q[i]; i++; }
    g[i] = 0;
    comma = strchr(g, ',');
    if (comma) *comma = 0;
    {
      char path[512];
      struct stat st;
      const char *sp = strchr(g, ' ');
      if (sp) g[sp - g] = 0;
      if (g[0] && strchr(g, '/')) {
        snprintf(path, sizeof path, "%s/%s", root, g);
        if (stat(path, &st) != 0) {
          fprintf(stderr, "FAIL\tlint\tgrantee path missing: %s\n", g);
          fail = 1;
        }
      }
    }
    p = q + i;
  }
  free(h);
  free(j);
  if (fail) return 1;
  printf("OK\tlint\tcap_table.json matches caps.h symbols and paths\n");
  return 0;
}
