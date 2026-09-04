/* OPEN-89..92: expand $(const), detect file change, emit add.s64 PTX, metal canary. */
#include "chs_rt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>

static OoStr oo_vis_from_bytes(const char *p, long long n) {
  OoStr r;
  if (!p || n <= 0) return oo_str_lit("");
  r.len = n;
  r.data = oo_str_alloc_payload((size_t)n);
  memcpy(r.data, p, (size_t)n);
  return r;
}

static const char *oo_vis_skip(const char *s, const char *e) {
  while (s < e && (*s == ' ' || *s == '\t')) s++;
  return s;
}

static long long oo_vis_eval(const char **ps, const char *e, int *ok);

static long long oo_vis_prim(const char **ps, const char *e, int *ok) {
  const char *s = oo_vis_skip(*ps, e);
  long long v = 0;
  int neg = 0;
  if (s < e && *s == '(') {
    s++;
    *ps = s;
    v = oo_vis_eval(ps, e, ok);
    s = oo_vis_skip(*ps, e);
    if (s < e && *s == ')') s++;
    else *ok = 0;
    *ps = s;
    return v;
  }
  if (s < e && *s == '-') { neg = 1; s++; }
  if (s >= e || !isdigit((unsigned char)*s)) { *ok = 0; *ps = s; return 0; }
  while (s < e && isdigit((unsigned char)*s)) {
    v = v * 10 + (*s - '0');
    s++;
  }
  *ps = s;
  return neg ? -v : v;
}

static long long oo_vis_mul(const char **ps, const char *e, int *ok) {
  long long v = oo_vis_prim(ps, e, ok);
  const char *s;
  while (*ok) {
    s = oo_vis_skip(*ps, e);
    if (s < e && (*s == '*' || *s == '/' || *s == '%')) {
      char op = *s++;
      long long r;
      *ps = s;
      r = oo_vis_prim(ps, e, ok);
      if (!*ok) return v;
      if (op == '*') v = v * r;
      else if (r == 0) { *ok = 0; return 0; }
      else if (op == '/') v = v / r;
      else v = v % r;
    } else break;
  }
  return v;
}

static long long oo_vis_eval(const char **ps, const char *e, int *ok) {
  long long v = oo_vis_mul(ps, e, ok);
  const char *s;
  while (*ok) {
    s = oo_vis_skip(*ps, e);
    if (s < e && (*s == '+' || *s == '-')) {
      char op = *s++;
      long long r;
      *ps = s;
      r = oo_vis_mul(ps, e, ok);
      if (!*ok) return v;
      v = (op == '+') ? v + r : v - r;
    } else break;
  }
  return v;
}

/* Expand $(const-int-expr). Other text is copied. */
OoStr oo_str_macro_expand(OoStr src) {
  char out[2048];
  long long oi = 0;
  long long i = 0;
  if (!src.data || src.len <= 0) return oo_str_lit("");
  while (i < src.len && oi < 2040) {
    if (i + 1 < src.len && src.data[i] == '$' && src.data[i + 1] == '(') {
      long long j = i + 2;
      int depth = 1;
      int ok = 1;
      const char *ps;
      long long v;
      char num[32];
      int nl;
      while (j < src.len && depth > 0) {
        if (src.data[j] == '(') depth++;
        else if (src.data[j] == ')') depth--;
        j++;
      }
      if (depth != 0) { out[oi++] = src.data[i++]; continue; }
      ps = src.data + i + 2;
      v = oo_vis_eval(&ps, src.data + j - 1, &ok);
      if (!ok) { out[oi++] = src.data[i++]; continue; }
      nl = snprintf(num, sizeof num, "%lld", (long long)v);
      if (nl > 0 && oi + nl < 2040) {
        memcpy(out + oi, num, (size_t)nl);
        oi += nl;
      }
      i = j;
    } else {
      out[oi++] = src.data[i++];
    }
  }
  return oo_vis_from_bytes(out, oi);
}

OoStr oo_str_ast_macro(OoStr src) { return oo_str_macro_expand(src); }

#define OO_HR_SLOTS 8
static char g_hr_path[OO_HR_SLOTS][PATH_MAX];
static char g_hr_hash[OO_HR_SLOTS][65];
static int g_hr_n;

long long oo_hot_reload(OoStr path) {
  fprintf(stderr, "ERR\tcap\thot_reload: missing or forged capability\n");
  (void)path;
  exit(1);
  return 0;
}
/* 1 = first load or contents changed; 0 = same bytes as last call. */
long long oo_hot_reload_cap(long long cap, OoStr path) {
  char cpath[PATH_MAX];
  FILE *f;
  unsigned char buf[4096];
  unsigned long long h = 1469598103934665603ULL;
  size_t nr;
  char hex[65];
  int i, slot = -1;
  oo_cap_require_fsread(cap, "hot_reload");
  if (!path.data || path.len <= 0 || path.len >= PATH_MAX) return 0;
  memcpy(cpath, path.data, (size_t)path.len);
  cpath[path.len] = 0;
  f = fopen(cpath, "rb");
  if (!f) return 0;
  while ((nr = fread(buf, 1, sizeof buf, f)) > 0) {
    size_t k;
    for (k = 0; k < nr; k++) {
      h ^= buf[k];
      h *= 1099511628211ULL;
    }
  }
  fclose(f);
  snprintf(hex, sizeof hex, "%016llx", (unsigned long long)h);
  for (i = 0; i < g_hr_n; i++) {
    if (strcmp(g_hr_path[i], cpath) == 0) { slot = i; break; }
  }
  if (slot < 0) {
    if (g_hr_n >= OO_HR_SLOTS) return 1;
    slot = g_hr_n++;
    strncpy(g_hr_path[slot], cpath, PATH_MAX - 1);
    g_hr_path[slot][PATH_MAX - 1] = 0;
    strncpy(g_hr_hash[slot], hex, 64);
    g_hr_hash[slot][64] = 0;
    return 1;
  }
  if (strcmp(g_hr_hash[slot], hex) == 0) return 0;
  strncpy(g_hr_hash[slot], hex, 64);
  g_hr_hash[slot][64] = 0;
  return 1;
}

static const char k_ooda_ptx[] =
    ".version 7.0\n"
    ".target sm_70\n"
    ".address_size 64\n"
    ".visible .entry ooda_add(\n"
    "  .param .u64 a,\n"
    "  .param .u64 b,\n"
    "  .param .u64 c\n"
    ")\n"
    "{\n"
    "  .reg .u64 %rd<4>;\n"
    "  ld.param.u64 %rd0, [a];\n"
    "  ld.param.u64 %rd1, [b];\n"
    "  ld.global.u64 %rd2, [%rd0];\n"
    "  ld.global.u64 %rd3, [%rd1];\n"
    "  add.s64 %rd2, %rd2, %rd3;\n"
    "  ld.param.u64 %rd0, [c];\n"
    "  st.global.u64 [%rd0], %rd2;\n"
    "  ret;\n"
    "}\n";

static const char *fs_split_parent_vis(const char *p, char *out, size_t sz) {
  if (!p || !out || sz < 2) return NULL;
  const char *s = strrchr(p, '/'); if (!s) return NULL;
  if (s == p) { if (p[1] == '\0') return NULL; out[0] = '/'; out[1] = '\0'; return p + 1; }
  size_t n = (size_t)(s - p); if (n + 1 > sz) return NULL;
  memcpy(out, p, n); out[n] = '\0';
  return s[1] == '\0' ? NULL : s + 1;
}

static int vision_path_under_writedir(const char *path, const char *dir) {
  char rp[PATH_MAX], rd[PATH_MAX], par[PATH_MAX];
  if (!path || !dir || !dir[0] || !strcmp(dir, "/") || !realpath(dir, rd)) return 0;
  size_t n = strlen(rd); if (!n) return 0;
  if (realpath(path, rp)) return !strncmp(rp, rd, n) && (rp[n] == '\0' || rp[n] == '/');
  const char *b = fs_split_parent_vis(path, par, PATH_MAX);
  if (!b || !b[0] || !strcmp(b, ".") || !strcmp(b, "..") || strchr(b, '/') || !realpath(par, rp)) return 0;
  return !strncmp(rp, rd, n) && (rp[n] == '\0' || rp[n] == '/');
}

long long oo_emit_ptx_cap(long long cap, OoStr unused) {
  const char *dir = ".ooda-cache/ooda-tmp";
  char path[256];
  FILE *f;
  size_t n = sizeof k_ooda_ptx - 1;
  const char *wdir = oo_process_policy_getenv("OODA_FS_WRITEDIR");
  (void)unused;
  oo_cap_require_sys(cap, "emit_ptx");
  snprintf(path, sizeof path, "%s/ooda_emit.ptx", dir);
  if (wdir && wdir[0] && !vision_path_under_writedir(path, wdir)) return 0;
  (void)mkdir(".ooda-cache", 0755);
  (void)mkdir(dir, 0755);
  f = fopen(path, "w");
  if (!f) return 0;
  if (fwrite(k_ooda_ptx, 1, n, f) != n) { fclose(f); return 0; }
  fclose(f);
  return (long long)n;
}

OoStr macro_expand(OoStr src) { return oo_str_macro_expand(src); }
OoStr ast_macro(OoStr src) { return oo_str_ast_macro(src); }
