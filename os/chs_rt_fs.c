#include "chs_rt.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
void oo_cap_require_fsread(long long got, const char *op);
void oo_cap_require_fswrite(long long got, const char *op);
void oo_cap_require_env(long long got, const char *op);
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
OoResS oo_read_file(long long cap, OoStr path) {
oo_cap_require_fsread(cap, "read_file"); OoResS r={0, oo_str_lit("read_file failed")};
char cpath[PATH_MAX];
if (!to_cpath(path, cpath, PATH_MAX)) return r;
if (!fs_read_confined(cpath)) return r;
FILE *f = fopen(cpath, "rb"); if (!f) return r;
if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return r; }
long sz = ftell(f); if (sz < 0) { fclose(f); return r; }
if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return r; }
char *buf = oo_str_alloc_payload((size_t)sz);
size_t n = fread(buf, 1, (size_t)sz, f);
if (ferror(f)) { oo_str_release((OoStr){buf, (long long)n}); fclose(f); return r; }
buf[n] = 0; fclose(f);
r.ok = 1; r.val.data = buf; r.val.len = (long long)n;
return r;
}
int oo_is_policy_path(const char *p);
int oo_policy_write_on(void);
static int policy_locked(const char *p) {
return oo_is_policy_path(p) && !oo_policy_write_on();
}
OoResV oo_write_file(long long cap, OoStr path, OoStr content) {
oo_cap_require_fswrite(cap, "write_file"); OoResV r={0, oo_str_lit("write_file failed")};
char cpath[PATH_MAX];
if (!to_cpath(path, cpath, PATH_MAX)) return r;
const char *dir = oo_process_policy_getenv("OODA_FS_WRITEDIR");
if (!dir || !dir[0] || !path_under_writedir(cpath, dir)) {
r.err = oo_str_lit("write_file denied: path not under OODA_FS_WRITEDIR"); return r; }
if (content.len < 0) return r;
if (oo_is_policy_path(cpath) && !oo_policy_write_on()) {
r.err = oo_str_lit("write_file denied: policy path"); return r; }
int fd = writedir_open_trunc(cpath); if (fd < 0) return r;
FILE *f = fdopen(fd, "wb"); if (!f) { close(fd); return r; }
size_t want = content.data ? (size_t)content.len : 0;
int bad = (want && fwrite(content.data, 1, want, f) != want) || ferror(f);
if (fclose(f) != 0) bad = 1;
if (!bad) { r.ok = 1; r.err = oo_str_lit(""); }
return r;
}
int oo_path_exists(long long cap, OoStr path) {
oo_cap_require_fsread(cap, "path_exists");
char cpath[PATH_MAX];
if (!to_cpath(path, cpath, PATH_MAX)) return 0;
if (!fs_read_confined(cpath)) return 0;
FILE *f=fopen(cpath,"rb");
if(f){fclose(f);return 1;}
return 0;
}
long long oo_file_size(long long cap, OoStr path) {
oo_cap_require_fsread(cap, "file_size");
char cpath[PATH_MAX];
if (!to_cpath(path, cpath, PATH_MAX)) return -1;
if (!fs_read_confined(cpath)) return -1;
FILE *f=fopen(cpath,"rb"); if(!f)return -1;
fseek(f,0,SEEK_END); long long sz=ftell(f); fclose(f);
return sz;
}
OoResS oo_env_get(long long cap, OoStr key) {
oo_cap_require_env(cap, "env_get");
OoResS r;
const char *val = oo_process_policy_getenv(key.data ? key.data : "");
if (val) {
r.ok = 1;
r.val = oo_str_lit(val);
} else {
r.ok = 0;
r.val = oo_str_lit("env var not set");
}
return r;
}
long long oo_monotonic_us(void) {
struct timespec ts;
clock_gettime(CLOCK_MONOTONIC, &ts);
long long us = (long long)ts.tv_sec * 1000000LL + (long long)ts.tv_nsec / 1000LL;
return us > 0LL ? us : 1LL;
}
OoSList oo_fs_read_dir(long long cap, OoStr path) {
oo_cap_require_fsread(cap, "fs_read_dir");
OoSList l = oo_slist_new();
char cpath[PATH_MAX];
if (!to_cpath(path, cpath, PATH_MAX)) return l;
if (!fs_read_confined(cpath)) return l;
DIR *d = opendir(cpath);
if (!d) return l;
struct dirent *dir;
while ((dir = readdir(d)) != NULL) {
if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
OoStr part = oo_str_lit(dir->d_name);
OoSList next = oo_slist_push(l, part);
oo_slist_release(l);
l = next;
oo_str_release(part);
}
closedir(d);
return l;
}
int oo_fs_is_dir(long long cap, OoStr path) {
oo_cap_require_fsread(cap, "fs_is_dir");
char cpath[PATH_MAX];
if (!to_cpath(path, cpath, PATH_MAX)) return 0;
if (!fs_read_confined(cpath)) return 0;
struct stat st;
return (stat(cpath, &st) == 0 && S_ISDIR(st.st_mode)) ? 1 : 0;
}
OoResV oo_fs_remove_file(long long cap, OoStr path) {
oo_cap_require_fswrite(cap, "fs_remove_file");
char cpath[PATH_MAX];
if (!to_cpath(path, cpath, PATH_MAX)) { OoResV r={0, oo_str_lit("fs_remove_file failed")}; return r; }
OoResV r={0, oo_str_lit("fs_remove_file failed")};
const char *dir = oo_process_policy_getenv("OODA_FS_WRITEDIR");
if (!dir || !dir[0] || !path_under_writedir(cpath, dir)) {
r.err = oo_str_lit("fs_remove_file denied: path not under OODA_FS_WRITEDIR"); return r; }
if (policy_locked(cpath)) {
r.err = oo_str_lit("fs_remove_file denied: policy path"); return r; }
if (unlink(cpath) == 0) { r.ok = 1; r.err = oo_str_lit(""); }
return r;
}
OoResV oo_fs_rmdir(long long cap, OoStr path) {
oo_cap_require_fswrite(cap, "fs_rmdir");
char cpath[PATH_MAX];
if (!to_cpath(path, cpath, PATH_MAX)) { OoResV r={0, oo_str_lit("fs_rmdir failed")}; return r; }
OoResV r={0, oo_str_lit("fs_rmdir failed")};
const char *dir = oo_process_policy_getenv("OODA_FS_WRITEDIR");
if (!dir || !dir[0] || !path_under_writedir(cpath, dir)) {
r.err = oo_str_lit("fs_rmdir denied: path not under OODA_FS_WRITEDIR"); return r; }
if (policy_locked(cpath)) {
r.err = oo_str_lit("fs_rmdir denied: policy path"); return r; }
if (rmdir(cpath) == 0) { r.ok = 1; r.err = oo_str_lit(""); }
return r;
}
OoResV oo_fs_mkdir(long long cap, OoStr path) {
oo_cap_require_fswrite(cap, "fs_mkdir");
char cpath[PATH_MAX];
if (!to_cpath(path, cpath, PATH_MAX)) { OoResV r={0, oo_str_lit("fs_mkdir failed")}; return r; }
OoResV r={0, oo_str_lit("fs_mkdir failed")};
const char *dir = oo_process_policy_getenv("OODA_FS_WRITEDIR");
if (!dir || !dir[0] || !path_under_writedir(cpath, dir)) {
r.err = oo_str_lit("fs_mkdir denied: path not under OODA_FS_WRITEDIR"); return r; }
if (policy_locked(cpath)) {
r.err = oo_str_lit("fs_mkdir denied: policy path"); return r; }
if (mkdir(cpath, 0777) == 0) { r.ok = 1; r.err = oo_str_lit(""); }
return r;
}
OoResV oo_fs_hardlink(long long cap, OoStr oldpath, OoStr newpath) {
oo_cap_require_fswrite(cap, "fs_hardlink");
char cold[PATH_MAX], cnew[PATH_MAX];
if (!to_cpath(oldpath, cold, PATH_MAX) || !to_cpath(newpath, cnew, PATH_MAX)) {
OoResV bad={0,oo_str_lit("fs_hardlink failed")}; return bad;
}
OoResV r={0,oo_str_lit("fs_hardlink failed")}; const char *dir = oo_process_policy_getenv("OODA_FS_WRITEDIR");
if (!dir || !dir[0] || !path_under_writedir(cnew, dir) || !path_under_writedir(cold, dir)) { r.err=oo_str_lit("fs_hardlink denied"); return r; }
if (policy_locked(cold) || policy_locked(cnew)) {
r.err = oo_str_lit("fs_hardlink denied: policy path"); return r; }
if (link(cold, cnew) == 0) { r.ok = 1; r.err = oo_str_lit(""); }
return r;
}
OoResV oo_fs_symlink(long long cap, OoStr target, OoStr linkpath) {
oo_cap_require_fswrite(cap, "fs_symlink");
char ctarget[PATH_MAX], clink[PATH_MAX];
if (!to_cpath(target, ctarget, PATH_MAX) || !to_cpath(linkpath, clink, PATH_MAX)) {
OoResV bad={0,oo_str_lit("fs_symlink failed")}; return bad;
}
OoResV r={0,oo_str_lit("fs_symlink failed")}; const char *dir = oo_process_policy_getenv("OODA_FS_WRITEDIR");
if (!dir || !dir[0] || !path_under_writedir(clink, dir) || !path_under_writedir(ctarget, dir)) { r.err=oo_str_lit("fs_symlink denied"); return r; }
if (policy_locked(ctarget) || policy_locked(clink)) {
r.err = oo_str_lit("fs_symlink denied: policy path"); return r; }
if (symlink(ctarget, clink) == 0) { r.ok = 1; r.err = oo_str_lit(""); }
return r;
}
