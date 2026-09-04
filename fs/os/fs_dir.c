/* fs_dir.c — cap-gated directory operations: read_dir, is_dir, remove_file,
 * rmdir, mkdir, hardlink, symlink. All paths are subject to the OODA_FS_*
 * confinement (read confined via fs_lowlevel.c:fs_read_confined, write
 * confined via fs_lowlevel.c:path_under_writedir) and the policy-path gate.
 * Cap tokens: read_dir/is_dir need FsReadCap; remove_file/rmdir/mkdir/hardlink/
 * symlink need FsWriteCap. */
#include "../../oodar.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
/* internal helpers (defined in fs_lowlevel.c) */
int to_cpath(OoStr p, char *c, int max);
int fs_read_confined(const char *cpath);
int path_under_writedir(const char *path, const char *dir);
int policy_locked(const char *p);

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
