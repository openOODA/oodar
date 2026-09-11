/* fs_lowlevel.c — internal helpers used by fs.c and fs_dir.c.
 * Not part of the public ABI: path splits, cstring conversion, OODA_FS_*DIR
 * confinement, O_NOFOLLOW openat(2), and the policy-path gate.
 * The cap-gated public surface is in fs.c (file ops) and fs_dir.c (dir ops). */
#include "../../oodar.h"
#include "../../oodar_internal.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>

/* policy gates — implemented in fs/os/sys_env.c */
int oo_is_policy_path(const char *p);
int oo_policy_write_on(void);

static const char *fs_split_parent(const char *p, char *out, size_t sz) {
  if (!p || p[0] != '/' || !out || sz < 2) return NULL;
  const char *s = strrchr(p, '/');
  if (!s) return NULL;
  if (s == p) {
    if (p[1] == '\0') return NULL;
    out[0] = '/';
    out[1] = '\0';
    return p + 1;
  }
  size_t n = (size_t)(s - p);
  if (n + 1 > sz) return NULL;
  memcpy(out, p, n);
  out[n] = '\0';
  return s[1] == '\0' ? NULL : s + 1;
}

int to_cpath(OoStr p, char *c, int max) {
  long long i;
  if (!c || max < 2 || !p.data || p.len <= 0 || p.len >= max) return 0;
  for (i = 0; i < p.len; i++) {
    if (p.data[i] == '\0') return 0;
  }
  memcpy(c, p.data, (size_t)p.len);
  c[p.len] = '\0';
  return 1;
}

/* --- Confinement & Working Directory Cache --- */
#define OO_FS_DIR_CACHE_MAX 8

typedef struct {
  char dir[PATH_MAX];
  char rd[PATH_MAX];
  size_t rd_len;
} OoFsDirEntry;

static pthread_mutex_t g_fs_cache_mu = PTHREAD_MUTEX_INITIALIZER;
static OoFsDirEntry g_dir_cache[OO_FS_DIR_CACHE_MAX];
static int g_dir_cache_count = 0;

static char g_cached_cwd[PATH_MAX];
static size_t g_cached_cwd_len = 0;
static dev_t g_cached_cwd_dev = 0;
static ino_t g_cached_cwd_ino = 0;

static const char *fs_get_cached_cwd(char *out, size_t sz) {
  struct stat st;
  if (!out || sz < 2) return NULL;
  pthread_mutex_lock(&g_fs_cache_mu);
  if (stat(".", &st) != 0) {
    pthread_mutex_unlock(&g_fs_cache_mu);
    return NULL;
  }
  if (st.st_dev != g_cached_cwd_dev || st.st_ino != g_cached_cwd_ino || !g_cached_cwd_len) {
    if (!getcwd(g_cached_cwd, sizeof g_cached_cwd)) {
      pthread_mutex_unlock(&g_fs_cache_mu);
      return NULL;
    }
    g_cached_cwd_dev = st.st_dev;
    g_cached_cwd_ino = st.st_ino;
    g_cached_cwd_len = strlen(g_cached_cwd);
    g_dir_cache_count = 0;
    memset(g_dir_cache, 0, sizeof g_dir_cache);
  }
  if (g_cached_cwd_len + 1 > sz) {
    pthread_mutex_unlock(&g_fs_cache_mu);
    return NULL;
  }
  memcpy(out, g_cached_cwd, g_cached_cwd_len + 1);
  pthread_mutex_unlock(&g_fs_cache_mu);
  return out;
}

static const char *fs_make_abs(const char *path, char *buf, size_t sz) {
  if (!path || !path[0]) return NULL;
  if (path[0] == '/') return path;
  char cwd[PATH_MAX];
  if (!fs_get_cached_cwd(cwd, sizeof cwd)) return NULL;
  if (snprintf(buf, sz, "%s/%s", cwd, path) >= (int)sz) return NULL;
  return buf;
}

static int fs_resolve_dir(const char *dir, char *rd_out, size_t sz) {
  if (!dir || !dir[0] || !strcmp(dir, "/")) return 0;
  if (dir[0] != '/') {
    char dummy[PATH_MAX];
    if (!fs_get_cached_cwd(dummy, sizeof dummy)) return 0;
  }
  pthread_mutex_lock(&g_fs_cache_mu);
  for (int i = 0; i < g_dir_cache_count; i++) {
    if (strcmp(g_dir_cache[i].dir, dir) == 0) {
      if (g_dir_cache[i].rd_len + 1 > sz) {
        pthread_mutex_unlock(&g_fs_cache_mu);
        return 0;
      }
      memcpy(rd_out, g_dir_cache[i].rd, g_dir_cache[i].rd_len + 1);
      pthread_mutex_unlock(&g_fs_cache_mu);
      return 1;
    }
  }
  pthread_mutex_unlock(&g_fs_cache_mu);
  char abs_dir[PATH_MAX], rd[PATH_MAX];
  const char *check_dir = fs_make_abs(dir, abs_dir, sizeof abs_dir);
  if (!check_dir || !realpath(check_dir, rd)) return 0;
  size_t n = strlen(rd);
  if (!n || n + 1 > sz) return 0;
  pthread_mutex_lock(&g_fs_cache_mu);
  for (int i = 0; i < g_dir_cache_count; i++) {
    if (strcmp(g_dir_cache[i].dir, dir) == 0) {
      if (g_dir_cache[i].rd_len + 1 > sz) {
        pthread_mutex_unlock(&g_fs_cache_mu);
        return 0;
      }
      memcpy(rd_out, g_dir_cache[i].rd, g_dir_cache[i].rd_len + 1);
      pthread_mutex_unlock(&g_fs_cache_mu);
      return 1;
    }
  }
  if (g_dir_cache_count < OO_FS_DIR_CACHE_MAX) {
    int idx = g_dir_cache_count;
    strncpy(g_dir_cache[idx].dir, dir, sizeof(g_dir_cache[idx].dir) - 1);
    g_dir_cache[idx].dir[sizeof(g_dir_cache[idx].dir) - 1] = '\0';
    memcpy(g_dir_cache[idx].rd, rd, n + 1);
    g_dir_cache[idx].rd_len = n;
    g_dir_cache_count++;
  }
  pthread_mutex_unlock(&g_fs_cache_mu);
  memcpy(rd_out, rd, n + 1);
  return 1;
}

static int path_under_dir_one(const char *dir, const char *cpath) {
  char rp[PATH_MAX], rd[PATH_MAX], par[PATH_MAX], abs[PATH_MAX];
  if (!dir || !cpath || !strcmp(dir, "/")) return 0;
  const char *check = fs_make_abs(cpath, abs, sizeof abs);
  if (!check) return 0;
  if (!fs_resolve_dir(dir, rd, sizeof rd)) return 0;
  size_t n = strlen(rd);
  if (!n) return 0;
  if (realpath(check, rp)) return !strncmp(rp, rd, n) && (rp[n] == '\0' || rp[n] == '/');
  const char *b = fs_split_parent(check, par, sizeof par);
  if (!b || !b[0] || !strcmp(b, ".") || !strcmp(b, "..") || strchr(b, '/') || !realpath(par, rp))
    return 0;
  return !strncmp(rp, rd, n) && (rp[n] == '\0' || rp[n] == '/');
}

int path_under_writedir(const char *path, const char *dir) {
  char seg[PATH_MAX];
  const char *s;
  if (!path) return 0;
  if (path_under_dir_one("/tmp", path)) return 1;
  if (!dir) return 0;
  s = dir;
  for (;;) {
    const char *c = strchr(s, ':');
    size_t n = c ? (size_t)(c - s) : strlen(s);
    if (n == 0) { if (!c) break; s = c + 1; continue; }
    if (n >= sizeof seg) return 0;
    memcpy(seg, s, n);
    seg[n] = 0;
    if (!strcmp(seg, "/")) return 0;
    if (path_under_dir_one(seg, path)) return 1;
    if (!c) break;
    s = c + 1;
  }
  return 0;
}

static int path_under_readdir(const char *path, const char *dir) {
  return path_under_writedir(path, dir);
}

int fs_jail_disabled(void) {
  const char *v = oo_process_policy_getenv("OODA_NO_JAIL");
  return v && v[0] == '1' && !v[1];
}

int fs_read_confined(const char *cpath) {
  if (fs_jail_disabled()) return 1;
  const char *rd = oo_process_policy_getenv("OODA_FS_READDIR");
  const char *wd = oo_process_policy_getenv("OODA_FS_WRITEDIR");
  char abs[PATH_MAX], rd_abs[PATH_MAX], wd_abs[PATH_MAX], cwd_buf[PATH_MAX];
  const char *check = fs_make_abs(cpath, abs, sizeof abs);
  if (!check) return 0;
  const char *rd_check = rd;
  const char *wd_check = wd;
  if ((!rd || !rd[0]) && (!wd || !wd[0])) {
    rd_check = fs_get_cached_cwd(cwd_buf, sizeof cwd_buf);
    if (!rd_check) return 0;
  }
  if (rd_check && rd_check[0] && rd_check[0] != '/') {
    rd_check = fs_make_abs(rd_check, rd_abs, sizeof rd_abs);
    if (!rd_check) return 0;
  }
  if (wd_check && wd_check[0] && wd_check[0] != '/') {
    wd_check = fs_make_abs(wd_check, wd_abs, sizeof wd_abs);
    if (!wd_check) return 0;
  }
  if (rd_check && rd_check[0] && path_under_readdir(check, rd_check)) return 1;
  if (wd_check && wd_check[0] && path_under_writedir(check, wd_check)) return 1;
  return 0;
}

static int fs_openat_parent(const char *path, int flags, mode_t mode) {
  char par[PATH_MAX], rp[PATH_MAX], abs[PATH_MAX];
  const char *check = fs_make_abs(path, abs, sizeof abs);
  if (!check) return -1;
  const char *b = fs_split_parent(check, par, sizeof par);
  if (!b || !b[0] || !strcmp(b, ".") || !strcmp(b, "..") || !realpath(par, rp)) return -1;
  int dfd = open(rp, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd < 0) return -1;
  int fd = openat(dfd, b, flags, mode);
  close(dfd);
  return fd;
}

int writedir_open_trunc(const char *path) {
  return fs_openat_parent(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0666);
}

int writedir_open_append(const char *path) {
  return fs_openat_parent(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0666);
}

int fs_open_ro_nofollow(const char *path) {
  return fs_openat_parent(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
}

int policy_locked(const char *p) {
  return oo_is_policy_path(p) && !oo_policy_write_on();
}
