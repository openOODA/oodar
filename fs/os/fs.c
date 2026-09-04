/* fs.c — high-level cap-gated file ops. The dir operations live in fs_dir.c
 * and the path-confinement + openat(2) helpers live in fs_lowlevel.c.
 * oo_env_get is in fs/os/sys_env.c (it's an env-typed op, not a file op).
 * Cap tokens: oo_read_file/oo_path_exists/oo_file_size need FsReadCap
 * (oo_cap_require_fsread); oo_write_file needs FsWriteCap (oo_cap_require_fswrite). */
#include "../../oodar.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/* internal helpers (defined in fs_lowlevel.c) */
int to_cpath(OoStr p, char *c, int max);
int fs_read_confined(const char *cpath);
int writedir_open_trunc(const char *path);
int path_under_writedir(const char *path, const char *dir);
int oo_is_policy_path(const char *p);
int oo_policy_write_on(void);

OoResS oo_read_file(long long cap, OoStr path) {
char cpath[PATH_MAX];
oo_cap_require_fsread(cap, "read_file"); OoResS r={0, oo_str_lit("read_file failed")};
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
long long oo_monotonic_us(void) {
struct timespec ts;
clock_gettime(CLOCK_MONOTONIC, &ts);
long long us = (long long)ts.tv_sec * 1000000LL + (long long)ts.tv_nsec / 1000LL;
return us > 0LL ? us : 1LL;
}
