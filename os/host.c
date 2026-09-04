#include "../oodar.h"

/* ----- Host FFI wrappers (symbols from optional host staticlib) -----
 * Only compiled when OODA_WITH_HOST_FFI is set (programs that call
 * host_build / host_* dumps). Pure CHS links without host FFI.
 *
 * Pure emit preamble deliberately does NOT declare these symbols
 * (see oodac/c_emit_preamble.oo). Pure product binaries must not
 * reference them; this TU stays for optional host FFI builds only.
 */
#ifdef OODA_WITH_HOST_FFI
extern char *ooda_host_ast_dump(const char *path);
extern char *ooda_host_check(const char *path);
extern char *ooda_host_token_dump(const char *path);
extern int ooda_host_build(const char *src, const char *out_bin);
extern void ooda_host_free(char *p);

static OoStr oo_from_c_heap(char *p) {
  if (!p) return oo_str_lit("ERR\thost\tnull\n");
  OoStr r = oo_str_lit(p);
  ooda_host_free(p);
  return r;
}

OoStr oo_host_ast_dump(long long cap, OoStr path) {
  oo_cap_require_ffi(cap, "ast_dump");
  return oo_from_c_heap(ooda_host_ast_dump(path.data));
}
OoStr oo_host_check(long long cap, OoStr path) {
  oo_cap_require_ffi(cap, "check");
  return oo_from_c_heap(ooda_host_check(path.data));
}
OoStr oo_host_token_dump(long long cap, OoStr path) {
  oo_cap_require_ffi(cap, "token_dump");
  return oo_from_c_heap(ooda_host_token_dump(path.data));
}

OoResS oo_host_build(long long cap, OoStr src, OoStr out_bin) {
  oo_cap_require_ffi(cap, "host_build");
  OoResS r;
  int rc = ooda_host_build(src.data, out_bin.data);
  if (rc == 0) {
    r.ok = 1;
    r.val = out_bin;
  } else {
    r.ok = 0;
    r.val = oo_str_lit("host_build failed");
  }
  return r;
}
#endif /* OODA_WITH_HOST_FFI */
