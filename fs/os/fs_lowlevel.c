/* fs_lowlevel.c — internal helpers used by fs.c and fs_dir.c.
 * Not part of the public ABI: path splits, cstring conversion, OODA_FS_*DIR
 * confinement, O_NOFOLLOW openat(2), and the policy-path gate.
 * The cap-gated public surface is in fs.c (file ops) and fs_dir.c (dir ops). */
#include "../../oodar.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
/* policy gates — implemented in fs/os/sys_env.c */
int oo_is_policy_path(const char *p);
int oo_policy_write_on(void);

static const char *fs_split_parent(const char *p, char *out, size_t sz) {
if(!p||p[0]!='/'||!out||sz<2)return NULL;
const char *s=strrchr(p,'/'); if(!s)return NULL;
if(s==p){ if(p[1]=='\0')return NULL; out[0]='/'; out[1]='\0'; return p+1; }
size_t n=(size_t)(s-p); if(n+1>sz)return NULL;
memcpy(out,p,n); out[n]='\0';
return s[1]=='\0'?NULL:s+1;
}
static int to_cpath(OoStr p, char* c, int max) {
long long i;
if (!c || max < 2 || !p.data || p.len <= 0 || p.len >= max) return 0;
for (i = 0; i < p.len; i++) {
if (p.data[i] == '\0') return 0;
}
memcpy(c, p.data, (size_t)p.len);
c[p.len] = '\0';
return 1;
}
static int path_under_writedir(const char *path, const char *dir) {
char rp[PATH_MAX], rd[PATH_MAX], par[PATH_MAX], abs[PATH_MAX];
const char *check = path;
if(!path||!dir||!strcmp(dir,"/"))return 0;
if (path[0] != '/') {
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof cwd)) return 0;
  if (snprintf(abs, sizeof abs, "%s/%s", cwd, path) >= (int)sizeof abs) return 0;
  check = abs;
}
if (!realpath(dir, rd)) return 0;
size_t n = strlen(rd); if(!n)return 0;
if (realpath(check, rp)) return !strncmp(rp,rd,n) && (rp[n]=='\0'||rp[n]=='/');
const char *b = fs_split_parent(check, par, PATH_MAX);
if(!b||!b[0]||!strcmp(b,".")||!strcmp(b,"..")||strchr(b,'/')||!realpath(par,rp))return 0;
return !strncmp(rp,rd,n) && (rp[n]=='\0'||rp[n]=='/');
}
static int path_under_readdir(const char *path, const char *dir) {
char rp[PATH_MAX], rd[PATH_MAX], par[PATH_MAX], abs[PATH_MAX];
const char *check = path;
if(!path||!dir||!strcmp(dir,"/"))return 0;
if (path[0] != '/') {
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof cwd)) return 0;
  if (snprintf(abs, sizeof abs, "%s/%s", cwd, path) >= (int)sizeof abs) return 0;
  check = abs;
}
if (!realpath(dir, rd)) return 0;
size_t n = strlen(rd); if(!n)return 0;
if (realpath(check, rp)) return !strncmp(rp,rd,n) && (rp[n]=='\0'||rp[n]=='/');
const char *b = fs_split_parent(check, par, PATH_MAX);
if(!b||!b[0]||!strcmp(b,".")||!strcmp(b,"..")||strchr(b,'/')||!realpath(par,rp))return 0;
return !strncmp(rp,rd,n) && (rp[n]=='\0'||rp[n]=='/');
}
static int fs_read_confined(const char *cpath) {
const char *rd = oo_process_policy_getenv("OODA_FS_READDIR");
const char *wd = oo_process_policy_getenv("OODA_FS_WRITEDIR");
char abs[PATH_MAX], rd_abs[PATH_MAX], wd_abs[PATH_MAX], cwd_def[PATH_MAX];
const char *check = cpath;
const char *rd_check = rd;
const char *wd_check = wd;
if ((!rd || !rd[0]) && (!wd || !wd[0])) {
  if (getcwd(cwd_def, sizeof cwd_def)) rd_check = cwd_def;
}
if (cpath[0] != '/') {
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof cwd)) return 0;
  if (snprintf(abs, sizeof abs, "%s/%s", cwd, cpath) >= (int)sizeof abs) return 0;
  check = abs;
}
if (rd_check && rd_check[0] && rd_check[0] != '/') {
  char cwd2[PATH_MAX];
  if (!getcwd(cwd2, sizeof cwd2)) return 0;
  if (snprintf(rd_abs, sizeof rd_abs, "%s/%s", cwd2, rd_check) >= (int)sizeof rd_abs) return 0;
  rd_check = rd_abs;
}
if (wd && wd[0] && wd[0] != '/') {
  char cwd3[PATH_MAX];
  if (!getcwd(cwd3, sizeof cwd3)) return 0;
  if (snprintf(wd_abs, sizeof wd_abs, "%s/%s", cwd3, wd) >= (int)sizeof wd_abs) return 0;
  wd_check = wd_abs;
}
if (rd_check && rd_check[0] && path_under_readdir(check, rd_check)) return 1;
if (wd_check && wd_check[0] && path_under_writedir(check, wd_check)) return 1;
return 0;
}
static int writedir_open_trunc(const char *path) {
char par[PATH_MAX], rp[PATH_MAX], abs[PATH_MAX];
const char *check = path;
if (path[0] != '/') {
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof cwd)) return -1;
  if (snprintf(abs, sizeof abs, "%s/%s", cwd, path) >= (int)sizeof abs) return -1;
  check = abs;
}
const char *b = fs_split_parent(check, par, PATH_MAX);
if(!b||!b[0]||!strcmp(b,".")||!strcmp(b,"..")||!realpath(par,rp))return -1;
int dfd = open(rp, O_RDONLY|O_DIRECTORY|O_CLOEXEC); if(dfd<0)return -1;
int fd = openat(dfd, b, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW, 0666);
close(dfd); return fd;
}
static int policy_locked(const char *p) {
return oo_is_policy_path(p) && !oo_policy_write_on();
}
