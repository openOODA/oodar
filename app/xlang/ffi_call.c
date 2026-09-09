/* Typed ffi_call of dlsym-resolved symbols (split from ffi.c per 256-line cap).
 * Fixed-arity pass-through, max 6 args; int/pointer kinds only. */
#include "../../oodar.h"
#include "../../oodar_internal.h"
#include <string.h>
#include <stdio.h>
/* Parse a pointer token ("sym:%p" from dlsym, "ptr:%p" from ffi_call).
 * Returns 0 with *out set, or -1. Never dereferences. */
static int ffi_parse_ptr(const char *s, size_t n, void **out) {
  char tmp[32];
  void *p = NULL;
  if (!s || n < 5) return -1;
  if (strncmp(s, "sym:", 4) != 0 && strncmp(s, "ptr:", 4) != 0) return -1;
  if (n - 4 >= sizeof tmp) return -1;
  memcpy(tmp, s + 4, n - 4);
  tmp[n - 4] = '\0';
  if (sscanf(tmp, "%p", &p) != 1 || !p) return -1;
  if (out) *out = p;
  return 0;
}

/* Fixed-arity pass-through stubs (SysV AMD64: int/pointer args share the
 * 64-bit slots; int-kind values are range-checked at conversion, int
 * returns are truncated per rspec). Float/struct/varargs unsupported. */
static long long ffi_call_n(void *f, int argc, long long *a) {
  switch (argc) {
  case 0: return ((long long (*)())f)();
  case 1: return ((long long (*)(long long))f)(a[0]);
  case 2: return ((long long (*)(long long, long long))f)(a[0], a[1]);
  case 3: return ((long long (*)(long long, long long, long long))f)(a[0], a[1], a[2]);
  case 4: return ((long long (*)(long long, long long, long long, long long))f)(a[0], a[1], a[2], a[3]);
  case 5: return ((long long (*)(long long, long long, long long, long long, long long))f)(a[0], a[1], a[2], a[3], a[4]);
  default: return ((long long (*)(long long, long long, long long, long long, long long, long long))f)(a[0], a[1], a[2], a[3], a[4], a[5]);
  }
}

/* Call a dlsym-resolved symbol. sym: "sym:%p" token. rspec: i u l p v.
 * aspec: one kind char per arg (i=int32 u=uint32 l=int64 p=pointer
 * s=string). argv: fields joined by tab, exactly strlen(aspec) of them.
 * Max 6 args. String args pass argv field bytes, valid for the call only. */
OoResS oo_ffi_call(long long cap, OoStr sym, OoStr rspec, OoStr aspec, OoStr argv) {
  OoResS r;
  void *fn = NULL;
  long long args[6];
  const char *fp[6];
  size_t fl[6];
  char sbuf[6][1024];
  char num[64];
  char out[96];
  int argc = 0;
  int i;
  oo_cap_require_ffi(cap, "ffi_call");
  r.ok = 0;
  if (ffi_parse_ptr(sym.data ? sym.data : "", sym.data ? (size_t)sym.len : 0, &fn) != 0) {
    r.val = oo_str_lit("ffi_call: invalid symbol token");
    return r;
  }
  if (!rspec.data || rspec.len != 1 || !strchr("iulpv", rspec.data[0])) {
    r.val = oo_str_lit("ffi_call: rspec must be one of i u l p v");
    return r;
  }
  if (!aspec.data) {
    r.val = oo_str_lit("ffi_call: aspec missing");
    return r;
  }
  argc = (int)aspec.len;
  if (argc < 0 || argc > 6) {
    r.val = oo_str_lit("ffi_call: 0..6 args");
    return r;
  }
  for (i = 0; i < argc; i++) {
    if (!strchr("iulps", aspec.data[i])) {
      r.val = oo_str_lit("ffi_call: aspec kinds are i u l p s");
      return r;
    }
  }
  if (argc == 0) {
    if (argv.data && argv.len != 0) {
      r.val = oo_str_lit("ffi_call: argv must be empty for 0 args");
      return r;
    }
  } else {
    int nf = 1;
    size_t k;
    size_t start = 0;
    int f = 0;
    if (!argv.data) {
      r.val = oo_str_lit("ffi_call: argv missing");
      return r;
    }
    for (k = 0; k < (size_t)argv.len; k++) if (argv.data[k] == '\t') nf++;
    if (nf != argc) {
      r.val = oo_str_lit("ffi_call: argv field count must match aspec");
      return r;
    }
    for (k = 0; k <= (size_t)argv.len; k++) {
      if (k == (size_t)argv.len || argv.data[k] == '\t') {
        fp[f] = argv.data + start;
        fl[f] = k - start;
        f++;
        start = k + 1;
      }
    }
  }
  for (i = 0; i < argc; i++) {
    char k = aspec.data[i];
    if (k == 's') {
      if (fl[i] > sizeof sbuf[i] - 1) {
        r.val = oo_str_lit("ffi_call: string arg too long");
        return r;
      }
      memcpy(sbuf[i], fp[i], fl[i]);
      sbuf[i][fl[i]] = '\0';
      args[i] = (long long)(intptr_t)sbuf[i];
    } else if (k == 'p') {
      void *p = NULL;
      if (ffi_parse_ptr(fp[i], fl[i], &p) != 0) {
        r.val = oo_str_lit("ffi_call: invalid pointer token");
        return r;
      }
      args[i] = (long long)(intptr_t)p;
    } else {
      char *end = NULL;
      long long v;
      if (fl[i] == 0 || fl[i] >= sizeof num) {
        r.val = oo_str_lit("ffi_call: bad integer field");
        return r;
      }
      memcpy(num, fp[i], fl[i]);
      num[fl[i]] = '\0';
      if (k == 'u') {
        unsigned long u = strtoul(num, &end, 10);
        if (!end || *end || num[0] == '-' || u > 4294967295UL) {
          r.val = oo_str_lit("ffi_call: uint32 out of range");
          return r;
        }
        args[i] = (long long)u;
      } else {
        v = strtoll(num, &end, 10);
        if (!end || *end) {
          r.val = oo_str_lit("ffi_call: bad integer field");
          return r;
        }
        if (k == 'i' && (v < -2147483648LL || v > 2147483647LL)) {
          r.val = oo_str_lit("ffi_call: int32 out of range");
          return r;
        }
        args[i] = v;
      }
    }
  }
  {
    long long ret = ffi_call_n(fn, argc, args);
    char rc = rspec.data[0];
    r.ok = 1;
    if (rc == 'v') {
      r.val = oo_str_lit("");
    } else if (rc == 'p') {
      snprintf(out, sizeof out, "ptr:%p", (void *)(intptr_t)ret);
      r.val = oo_str_lit(out);
    } else if (rc == 'u') {
      snprintf(out, sizeof out, "%u", (unsigned int)ret);
      r.val = oo_str_lit(out);
    } else if (rc == 'l') {
      snprintf(out, sizeof out, "%lld", ret);
      r.val = oo_str_lit(out);
    } else {
      snprintf(out, sizeof out, "%d", (int)ret);
      r.val = oo_str_lit(out);
    }
    return r;
  }
}
