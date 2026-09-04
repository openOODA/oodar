/* sys_stamp.c — fast cache key for a file path (size:mtime:nsec).
 * Avoids hashing whole compiler sources. v3.0.0: FsReadCap-gated because
 * stat(2) is a metadata read of a file path. */
#include "../../oodar.h"
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

OoStr oo_file_stamp(long long cap, OoStr path) {
  char cpath[PATH_MAX];
  struct stat st;
  char buf[96];
  oo_cap_require_fsread(cap, "file_stamp");
  if (!path.data || path.len <= 0 || path.len >= PATH_MAX) return oo_str_lit("0:0:0");
  memcpy(cpath, path.data, (size_t)path.len);
  cpath[path.len] = 0;
  if (stat(cpath, &st) != 0) return oo_str_lit("0:0:0");
#if defined(__APPLE__)
  snprintf(buf, sizeof buf, "%lld:%lld:%lld", (long long)st.st_size, (long long)st.st_mtimespec.tv_sec, (long long)st.st_mtimespec.tv_nsec);
#elif defined(_WIN32)
  snprintf(buf, sizeof buf, "%lld:%lld:0", (long long)st.st_size, (long long)st.st_mtime);
#else
  snprintf(buf, sizeof buf, "%lld:%lld:%lld", (long long)st.st_size, (long long)st.st_mtim.tv_sec, (long long)st.st_mtim.tv_nsec);
#endif
  return oo_str_lit(buf);
}
