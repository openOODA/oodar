/* Emit-C process state. oodac is single-threaded; stdout is the C stream. */
#include "chs_rt.h"

static int g_tn, g_np, g_nm;
static int g_marks[64];
static char g_names[256][16];

void oo_emit_tmp_reset(void) {
  g_tn = 0;
  g_np = 0;
  g_nm = 0;
}

void oo_emit_tmp_enter(void) {
  if (g_nm >= 64) abort();
  g_marks[g_nm++] = g_np;
}

void oo_emit_tmp_release_print(void) {
  int old = 0;
  int i;
  if (g_nm > 0) old = g_marks[g_nm - 1];
  i = g_np;
  while (i > old) {
    i--;
    printf("  oo_str_release(%s);\n", g_names[i]);
  }
}

void oo_emit_tmp_leave(void) {
  int old;
  if (g_nm <= 0) return;
  old = g_marks[g_nm - 1];
  oo_emit_tmp_release_print();
  g_nm--;
  g_np = old;
}

void oo_emit_tmp_own(OoStr expr) {
  const char *want;
  size_t wn;
  if (g_np <= 0) return;
  if (!expr.data || expr.len <= 0) return;
  want = g_names[g_np - 1];
  wn = strlen(want);
  if ((long long)wn != expr.len) return;
  if (memcmp(expr.data, want, wn) != 0) return;
  g_np--;
}

void oo_emit_tmp_release_all_print(void) {
  int i = g_np;
  while (i > 0) {
    i--;
    printf("  oo_str_release(%s);\n", g_names[i]);
  }
}

OoStr oo_emit_tmp_bind(OoStr call) {
  int w;
  const char *p;
  int n;
  if (g_np >= 256) abort();
  w = snprintf(g_names[g_np], 16, "__t%d", g_tn++);
  if (w < 0) abort();
  p = call.data;
  n = (p && call.len > 0) ? (int)call.len : 0;
  printf("  OoStr %s = %.*s;\n", g_names[g_np], n, p ? p : "");
  {
    OoStr name = oo_str_intern_bytes(g_names[g_np], (long long)strlen(g_names[g_np]));
    g_np++;
    return name;
  }
}
