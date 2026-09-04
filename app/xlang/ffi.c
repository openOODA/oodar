#include "../../oodar.h"
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <pthread.h>

#define OO_FFI_HANDLE_SLOTS 16
static void *g_ffi_handles[OO_FFI_HANDLE_SLOTS];
static pthread_mutex_t g_ffi_handles_mu = PTHREAD_MUTEX_INITIALIZER;
/* Process-wide serialize for entire oo_dlopen critical path (not recursive). */
static pthread_mutex_t g_ffi_dlopen_mu = PTHREAD_MUTEX_INITIALIZER;
/* Same-thread nested oo_dlopen depth (constructor re-entry). */
static __thread int g_ffi_dlopen_depth;

/* Register h in a free slot; 0 on success, -1 if full. Idempotent if h already
 * present. Keys are the returned handle:%p strings (lookup by format match).
 * Holds g_ffi_handles_mu for the whole scan/write only (no dlopen under it). */
static int ffi_handle_register(void *h) {
  int i;
  int free_i = -1;
  if (!h) return -1;
  pthread_mutex_lock(&g_ffi_handles_mu);
  for (i = 0; i < OO_FFI_HANDLE_SLOTS; i++) {
    if (g_ffi_handles[i] == h) { pthread_mutex_unlock(&g_ffi_handles_mu); return 0; }
    if (g_ffi_handles[i] == NULL && free_i < 0) free_i = i;
  }
  if (free_i < 0) { pthread_mutex_unlock(&g_ffi_handles_mu); return -1; }
  g_ffi_handles[free_i] = h;
  pthread_mutex_unlock(&g_ffi_handles_mu);
  return 0;
}

/* Lookup by handle string key "handle:%p". Returns slot index or -1.
 * Copies void* out while still holding g_ffi_handles_mu. */
static int ffi_handle_lookup(const char *key, void **out) {
  int i;
  int rc;
  char buf[96];
  if (!key || !key[0]) return -1;
  pthread_mutex_lock(&g_ffi_handles_mu);
  for (i = 0; i < OO_FFI_HANDLE_SLOTS; i++) {
    if (!g_ffi_handles[i]) continue;
    snprintf(buf, sizeof buf, "handle:%p", g_ffi_handles[i]);
    if (strcmp(buf, key) == 0) {
      if (out) *out = g_ffi_handles[i];
      rc = i;
      pthread_mutex_unlock(&g_ffi_handles_mu);
      return rc;
    }
  }
  pthread_mutex_unlock(&g_ffi_handles_mu);
  return -1;
}

/* Atomically lookup + clear slot (ownership transfer for dlclose). Prevents
 * double-dlclose of the same registration. dlclose itself runs outside the lock. */
static int ffi_handle_take(const char *key, void **out) {
  int i;
  char buf[96];
  if (!key || !key[0]) return -1;
  pthread_mutex_lock(&g_ffi_handles_mu);
  for (i = 0; i < OO_FFI_HANDLE_SLOTS; i++) {
    if (!g_ffi_handles[i]) continue;
    snprintf(buf, sizeof buf, "handle:%p", g_ffi_handles[i]);
    if (strcmp(buf, key) == 0) {
      if (out) *out = g_ffi_handles[i];
      g_ffi_handles[i] = NULL;
      pthread_mutex_unlock(&g_ffi_handles_mu);
      return i;
    }
  }
  pthread_mutex_unlock(&g_ffi_handles_mu);
  return -1;
}

OoResS oo_dlopen(long long cap, OoStr path) {
  OoResS r;
  const char *allow;
  const char *dir;
  const char *p;
  void *h;
  char buf[96];
  char rp_path[PATH_MAX];
  oo_cap_require_ffi(cap, "dlopen");
  r.ok = 0;
  /* ZT: process-policy keys only (OODA_*) — not product env_get */
  allow = oo_process_policy_getenv("OODA_FFI_ALLOW_DLOPEN");
  dir = oo_process_policy_getenv("OODA_FFI_ALLOWDIR");
  p = path.data ? path.data : "";
  if (!allow || strcmp(allow, "1") != 0) {
    r.val = oo_str_lit("ffi residual: set OODA_FFI_ALLOW_DLOPEN=1 for OS dlopen");
    return r;
  }
  /* 4.5 path-A: refuse nested / re-entrant oo_dlopen (constructor callback).
   * Checked before taking g_ffi_dlopen_mu so same-thread re-entry fails closed
   * instead of deadlocking the non-recursive process-wide lock. */
  if (g_ffi_dlopen_depth > 0) {
    r.val = oo_str_lit("ffi residual: nested dlopen refused");
    return r;
  }
  if (!realpath(p, rp_path)) {
    r.val = oo_str_lit("dlopen: file not found");
    return r;
  }
  if (dir && dir[0]) {
    if (!path_under_allowdir(rp_path, dir)) {
      r.val = oo_str_lit("dlopen: path outside OODA_FFI_ALLOWDIR");
      return r;
    }
  } else {
    if (!path_under_sys_lib(rp_path)) {
      r.val = oo_str_lit("dlopen: path outside system lib dirs (/lib, /lib64, /usr/lib, /usr/lib64)");
      return r;
    }
  }
  if (!ffi_verify_signature(rp_path)) {
    r.val = oo_str_lit("dlopen: signature verification failed");
    return r;
  }
  pthread_mutex_lock(&g_ffi_dlopen_mu);
  g_ffi_dlopen_depth++;
  h = dlopen(rp_path, RTLD_NOW | RTLD_LOCAL);
  g_ffi_dlopen_depth--;
  pthread_mutex_unlock(&g_ffi_dlopen_mu);
  if (!h) {
    const char *err = dlerror();
    r.val = oo_str_lit(err ? err : "dlopen failed");
    return r;
  }
  if (ffi_handle_register(h) != 0) {
    dlclose(h);
    r.val = oo_str_lit("dlopen: max FFI handle capacity reached");
    return r;
  }
  snprintf(buf, sizeof buf, "handle:%p", h);
  r.ok = 1;
  r.val = oo_str_lit(buf);
  return r;
}

OoResS oo_dlsym(long long cap, OoStr handle, OoStr symbol) {
  OoResS r;
  const char *hk;
  const char *sym;
  void *h = NULL;
  void *ptr;
  char buf[96];
  oo_cap_require_ffi(cap, "dlsym");
  r.ok = 0;
  hk = handle.data ? handle.data : "";
  sym = symbol.data ? symbol.data : "";
  if (!sym || !sym[0]) {
    r.val = oo_str_lit("dlsym: empty symbol");
    return r;
  }
  if (ffi_handle_lookup(hk, &h) < 0 || !h) {
    r.val = oo_str_lit("dlsym: invalid or unregistered handle");
    return r;
  }
  (void)dlerror();
  ptr = dlsym(h, sym);
  if (!ptr) {
    const char *err = dlerror();
    r.val = oo_str_lit(err ? err : "symbol not found");
    return r;
  }
  snprintf(buf, sizeof buf, "sym:%p", ptr);
  r.ok = 1;
  r.val = oo_str_lit(buf);
  return r;
}

OoResS oo_dlclose(long long cap, OoStr handle) {
  OoResS r;
  const char *hk;
  void *h = NULL;
  oo_cap_require_ffi(cap, "dlclose");
  r.ok = 0;
  hk = handle.data ? handle.data : "";
  if (ffi_handle_take(hk, &h) < 0 || !h) {
    r.val = oo_str_lit("dlclose: invalid, unregistered, or double-closed handle");
    return r;
  }
  if (dlclose(h) != 0) {
    const char *err = dlerror();
    r.val = oo_str_lit(err ? err : "dlclose failed");
    return r;
  }
  r.ok = 1;
  r.val = oo_str_lit("");
  return r;
}
