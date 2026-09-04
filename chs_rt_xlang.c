/* OPEN-70: read a C header under include jail; gcc -flto two units via execvp. */
#include "chs_rt.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void oo_cap_require_ffi(long long got, const char *op);
void oo_cap_require_process(long long got, const char *op);

static int oo_xlang_cpath(OoStr hdr, char *out, size_t cap) {
  size_t n;
  size_t i;
  if (!hdr.data || hdr.len <= 0 || cap < 2) { out[0] = 0; return 0; }
  n = (size_t)hdr.len;
  if (n >= cap) return 0;
  for (i = 0; i < n; i++) {
    if (hdr.data[i] == '\0') return 0;
  }
  memcpy(out, hdr.data, n);
  out[n] = 0;
  return 1;
}

static int oo_xlang_rel_ok(const char *name) {
  size_t i;
  if (!name || !name[0] || name[0] == '/') return 0;
  if (strstr(name, "..")) return 0;
  for (i = 0; name[i]; i++) {
    char c = name[i];
    if (i > 200) return 0;
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '/'))
      return 0;
  }
  return 1;
}

static int oo_xlang_ident_ok(const char *s) {
  size_t i;
  if (!s || !s[0]) return 0;
  if (!((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') || s[0] == '_'))
    return 0;
  for (i = 1; s[i]; i++) {
    char c = s[i];
    if (i > 32) return 0;
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '_'))
      return 0;
  }
  return 1;
}

static int oo_xlang_under_include(const char *rp) {
  static const char *roots[] = { "/usr/include", "/usr/local/include" };
  size_t i;
  if (!rp || rp[0] != '/') return 0;
  for (i = 0; i < sizeof roots / sizeof roots[0]; i++) {
    size_t n = strlen(roots[i]);
    if (strncmp(rp, roots[i], n) == 0 && (rp[n] == '\0' || rp[n] == '/')) return 1;
  }
  return 0;
}

static long long oo_xlang_read_size(const char *path) {
  FILE *f;
  long n;
  char rp[PATH_MAX];
  if (!path || !path[0]) return 0;
  if (!realpath(path, rp)) return 0;
  if (!oo_xlang_under_include(rp)) return 0;
  f = fopen(rp, "rb");
  if (!f) return 0;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
  n = ftell(f);
  fclose(f);
  if (n < 0) return 0;
  return (long long)n;
}

long long oo_import_c(long long cap, OoStr hdr) {
  char name[256];
  char p1[512];
  char rp[PATH_MAX];
  long long n;
  oo_cap_require_ffi(cap, "import_c");
  if (!oo_xlang_cpath(hdr, name, sizeof name)) return 0;
  if (name[0] == '/') {
    if (!realpath(name, rp)) return 0;
    if (!oo_xlang_under_include(rp)) return 0;
    return oo_xlang_read_size(rp);
  }
  if (!oo_xlang_rel_ok(name)) return 0;
  snprintf(p1, sizeof p1, "/usr/include/%s", name);
  n = oo_xlang_read_size(p1);
  if (n > 0) return n;
  snprintf(p1, sizeof p1, "/usr/local/include/%s", name);
  return oo_xlang_read_size(p1);
}

long long oo_ffi_gen(long long cap, OoStr hdr) {
  return oo_import_c(cap, hdr);
}

static int oo_xlang_run(char *const argv[]) {
  pid_t pid;
  int st;
  if (!argv || !argv[0]) return -1;
  pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    oo_child_filter_env();
    execvp(argv[0], argv);
    _exit(127);
  }
  if (waitpid(pid, &st, 0) != pid) return -1;
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return -1;
  return 0;
}

long long oo_lto_xlang_link(long long cap, OoStr a, OoStr b) {
  char na[64];
  char nb[64];
  char *cc1[8];
  char *cc2[8];
  char *ld[8];
  const char *wdir;
  char rp_wdir[PATH_MAX];
  char rp_wd[PATH_MAX];
  oo_cap_require_process(cap, "lto_xlang_link");
  wdir = oo_process_policy_getenv("OODA_FS_WRITEDIR");
  if (!wdir || !wdir[0] || !realpath(wdir, rp_wdir)) return 1;
  if (!realpath(".ooda-cache/ooda-tmp", rp_wd) ||
      strncmp(rp_wd, rp_wdir, strlen(rp_wdir)) != 0 ||
      (rp_wd[strlen(rp_wdir)] != '\0' && rp_wd[strlen(rp_wdir)] != '/')) {
    return 1;
  }
  (void)mkdir(".ooda-cache", 0755);
  (void)mkdir(".ooda-cache/ooda-tmp", 0755);
  if (!oo_xlang_cpath(a, na, sizeof na)) return 1;
  if (!oo_xlang_cpath(b, nb, sizeof nb)) return 1;
  if (!oo_xlang_ident_ok(na) || !oo_xlang_ident_ok(nb)) return 1;
  {
    FILE *fa = fopen(".ooda-cache/ooda-tmp/ooda_lto_a.c", "w");
    FILE *fb = fopen(".ooda-cache/ooda-tmp/ooda_lto_b.c", "w");
    if (!fa || !fb) {
      if (fa) fclose(fa);
      if (fb) fclose(fb);
      return 1;
    }
    fprintf(fa, "int ooda_lto_%s(int x) { return x + 1; }\n", na);
    fprintf(fb,
            "extern int ooda_lto_%s(int);\n"
            "int main(void) { return ooda_lto_%s(41) == 42 ? 0 : 1; }\n",
            na, na);
    fclose(fa);
    fclose(fb);
  }
  cc1[0] = "gcc"; cc1[1] = "-flto"; cc1[2] = "-c"; cc1[3] = "-o";
  cc1[4] = ".ooda-cache/ooda-tmp/ooda_lto_a.o";
  cc1[5] = ".ooda-cache/ooda-tmp/ooda_lto_a.c"; cc1[6] = NULL;
  cc2[0] = "gcc"; cc2[1] = "-flto"; cc2[2] = "-c"; cc2[3] = "-o";
  cc2[4] = ".ooda-cache/ooda-tmp/ooda_lto_b.o";
  cc2[5] = ".ooda-cache/ooda-tmp/ooda_lto_b.c"; cc2[6] = NULL;
  ld[0] = "gcc"; ld[1] = "-flto"; ld[2] = "-o";
  ld[3] = ".ooda-cache/ooda-tmp/ooda_lto.bin";
  ld[4] = ".ooda-cache/ooda-tmp/ooda_lto_a.o";
  ld[5] = ".ooda-cache/ooda-tmp/ooda_lto_b.o"; ld[6] = NULL;
  if (oo_xlang_run(cc1) != 0) return 1;
  if (oo_xlang_run(cc2) != 0) return 1;
  if (oo_xlang_run(ld) != 0) return 1;
  return 0;
}
