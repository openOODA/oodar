/* qa/tests_lint_cap_table.c — verifies sec/cap/cap_table.json matches caps.h.
 *
 * Runs `python3 scripts/gen_cap_table.py` and diffs the structural
 * cap list against the canonical sec/cap/cap_table.json. Drift
 * between the C truth (caps.h) and the structural truth
 * (cap_table.json, consumed by lsp and oodac) is a polyrepo blocker
 * — the lsp verifier and oodac emit would see stale cap bit
 * positions.
 *
 * v3.1.1 added: the regeneration script + this CI test.
 *
 * Exit codes:
 *   0 — cap_table.json matches caps.h
 *   1 — drift detected; re-run scripts/gen_cap_table.py and reconcile
 *   2 — python3 not on PATH or script failed
 *
 * The test allows benign _comment / _version / _regen / rule_2_*
 * mismatches (the hand-curated file has richer metadata). It only
 * fails on structural drift: cap name, value, bit, implemented,
 * category, grantee, require, or subsumes.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int run(const char *cmd, char *out, size_t outsz) {
  FILE *p = popen(cmd, "r");
  if (!p) return -1;
  size_t n = fread(out, 1, outsz - 1, p);
  out[n] = 0;
  return pclose(p);
}

/* Extract the value of a top-level JSON string field. Returns 1 if found, 0 if not. */
static int get_string_field(const char *json, const char *key, char *out, size_t outsz) {
  char pat[256];
  snprintf(pat, sizeof pat, "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) return 0;
  p = strchr(p, ':');
  if (!p) return 0;
  p++;
  while (*p == ' ' || *p == '\t' || *p == '\n') p++;
  if (*p != '"') return 0;
  p++;
  size_t i = 0;
  while (*p && *p != '"' && i < outsz - 1) {
    if (*p == '\\' && *(p + 1)) { p += 2; continue; }
    out[i++] = *p++;
  }
  out[i] = 0;
  return 1;
}

/* Find each cap's "name" + "value" + "bit" + "implemented" + "category" +
 * "grantee" + "require" + "subsumes" and emit one line per cap. */
static int extract_caps(const char *json, FILE *out) {
  const char *p = json;
  while ((p = strstr(p, "\"caps\"")) != NULL) {
    p = strchr(p, '[');
    if (!p) break;
    p++;
    int depth = 1;
    while (*p && depth > 0) {
      if (*p == '[') depth++;
      else if (*p == ']') { depth--; p++; break; }
      else if (*p == '{') {
        const char *end = strchr(p, '}');
        if (!end) break;
        char buf[4096];
        size_t len = (size_t)(end - p + 1);
        if (len >= sizeof buf) { p = end + 1; continue; }
        memcpy(buf, p, len); buf[len] = 0;

        char name[64] = "", grantee[256] = "", require[64] = "", category[32] = "";
        int value = -1, bit = -1, implemented = -1;
        char subsumes[256] = "";
        get_string_field(buf, "name", name, sizeof name);
        get_string_field(buf, "grantee", grantee, sizeof grantee);
        get_string_field(buf, "require", require, sizeof require);
        get_string_field(buf, "category", category, sizeof category);
        get_string_field(buf, "subsumes", subsumes, sizeof subsumes);

        char vbuf[32] = "", bbuf[32] = "";
        const char *vp = strstr(buf, "\"value\"");
        if (vp) { vp = strchr(vp, ':'); if (vp) value = atoi(vp + 1); }
        const char *bp = strstr(buf, "\"bit\"");
        if (bp) { bp = strchr(bp, ':'); if (bp) bit = atoi(bp + 1); }
        char ibuf[16];
        if (strstr(buf, "\"implemented\": true")) implemented = 1;
        else if (strstr(buf, "\"implemented\": false")) implemented = 0;

        fprintf(out, "cap|%-16s|bit=%2d|val=%-10d|impl=%d|cat=%-12s|req=%-30s|sub=%-32s|grantee=%s\n",
                name, bit, value, implemented, category, require, subsumes, grantee);
        p = end + 1;
      } else p++;
    }
    break;
  }
  return 1;
}

int main(void) {
  char generated[1 << 16];
  char canonical[1 << 16];
  const char *repo_root = getenv("OODAR_REPO");
  if (!repo_root) repo_root = ".";
  char cmd[1024];
  snprintf(cmd, sizeof cmd,
           "cd %s && python3 scripts/gen_cap_table.py 2>&1", repo_root);
  int rc = run(cmd, generated, sizeof generated);
  if (rc != 0) {
    fprintf(stderr, "ERR\tlint\tgen_cap_table.py failed (rc=%d). Is python3 on PATH?\n", rc);
    return 2;
  }
  snprintf(cmd, sizeof cmd, "cat %s/sec/cap/cap_table.json", repo_root);
  if (run(cmd, canonical, sizeof canonical) != 0) {
    fprintf(stderr, "ERR\tlint\tcannot read sec/cap/cap_table.json\n");
    return 2;
  }

  /* Extract structural cap lists from both and diff. */
  FILE *g = tmpfile(), *c = tmpfile();
  if (!g || !c) { fprintf(stderr, "ERR\tlint\ttmpfile failed\n"); return 2; }
  extract_caps(generated, g);
  extract_caps(canonical, c);
  rewind(g); rewind(c);

  char gbuf[1 << 14] = "", cbuf[1 << 14] = "";
  fread(gbuf, 1, sizeof gbuf - 1, g); fclose(g);
  fread(cbuf, 1, sizeof cbuf - 1, c); fclose(c);

  if (strcmp(gbuf, cbuf) == 0) {
    int g_count = 0;
    for (const char *q = gbuf; (q = strstr(q, "cap|")) != NULL; q += 4) g_count++;
    printf("OK\tlint\tcap_table.json matches caps.h (%d caps; structural fields aligned)\n", g_count);
    return 0;
  }
  fprintf(stderr, "FAIL\tlint\tcap_table.json drift detected.\n");
  fprintf(stderr, "\tRun: python3 scripts/gen_cap_table.py > sec/cap/cap_table.json\n");
  fprintf(stderr, "\tThen reconcile the hand-curated grantee / require / subsumes fields.\n");
  fprintf(stderr, "\n--- generated (script) ---\n%s\n", gbuf);
  fprintf(stderr, "\n--- canonical (json) ---\n%s\n", cbuf);
  return 1;
}
