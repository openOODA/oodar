#ifndef OODAR_INTERNAL_H
#define OODAR_INTERNAL_H
/* Process-local helpers. Not part of the public oodar.h ABI.
 * Included only by umbrella TUs and the implementing .c files. */
const char *oo_process_policy_getenv(const char *key);
void oo_child_filter_env(void);
int path_under_allowdir(const char *rp, const char *dir);
int path_under_sys_lib(const char *rp);
int ffi_verify_signature(const char *path);
#endif
