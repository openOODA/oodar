#ifndef OODAR_INTERNAL_H
#define OODAR_INTERNAL_H
#include <sys/types.h>
#include <stddef.h>
/* Process-local helpers. Not part of the public oodar.h ABI.
 * Included only by umbrella TUs and the implementing .c files. */
const char *oo_process_policy_getenv(const char *key);
int fs_jail_disabled(void);
void oo_child_filter_env(void);
int path_under_allowdir(const char *rp, const char *dir);
int path_under_sys_lib(const char *rp);
int ffi_verify_signature(const char *path);
void *oo_tls_connect_fd(int fd, const char *host);
ssize_t oo_tls_write(void *sess, const void *buf, size_t len);
ssize_t oo_tls_read(void *sess, void *buf, size_t len);
void oo_tls_close(void *sess);
#endif
