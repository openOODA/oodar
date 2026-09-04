/* Symmetric subdir orchestrator — cap-gated HMAC and cap-signed CG.
 *
 * v2.3.0 file split: this file replaces the monolithic sec/crypto/crypto.c
 * for the cap/json/cg content that lived there but is out of scope for
 * the file-split's hash/HMAC/secure extraction (which live in
 * symmetric/hash.c, symmetric/hmac.c, and symmetric/secure.c).
 *
 * The umbrella order is:
 *   symmetric/secure.c   (crypto_secure_wipe, crypto_ct_cmp)
 *   symmetric/hash.c     (SHA-256, SHA-512, sha256_bytes used by HMAC)
 *   symmetric/hmac.c     (crypto_hmac_sha256_internal — used by cap_attenuate)
 *   symmetric/crypto.c   (this orchestrator: cap_attenuate, json, cg)
 *
 * json_*_internal and python_embed_internal are currently unused outside
 * this TU; they are preserved verbatim to avoid dropping any future caller. */
#include "../../../oodar.h"
#include "../crypto_internal.h"
/* v2.2.0: explicit include — oo_event_emit is called from this TU; relying
 * on the implicit-declaration fallback would hide a missing prototype under
 * -Wstrict-prototypes and is a latent bug if the signature ever changes. */
#include "../../../app/telemetry/event.h"
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

/* OPEN-72: child seal = HMAC-SHA256(parent_hmac, child_rights). Empty inputs fail closed. */
static OoStr cap_empty_str(void) {
  OoStr z; z.data = oo_str_alloc_payload(0); z.len = 0; return z;
}

OoStr cap_attenuate(OoStr parent_hmac, OoStr child_rights) {
  if (parent_hmac.len <= 0 || !parent_hmac.data || child_rights.len <= 0 || !child_rights.data)
    return cap_empty_str();
  oo_event_emit(oo_str_lit("cap.attenuate"));
  return crypto_hmac_sha256_internal(parent_hmac, child_rights);
}

int cap_attenuate_ok(OoStr parent_hmac, OoStr child_rights) {
  OoStr h;
  int ok;
  if (parent_hmac.len <= 0 || !parent_hmac.data || child_rights.len <= 0 || !child_rights.data)
    return 0;
  h = crypto_hmac_sha256_internal(parent_hmac, child_rights);
  ok = (h.len == 64);
  oo_str_release(h);
  return ok;
}

OoStr oo_cap_attenuate(OoStr parent_hmac, OoStr child_rights) {
  return cap_attenuate(parent_hmac, child_rights);
}

int oo_cap_attenuate_ok(OoStr parent_hmac, OoStr child_rights) {
  return cap_attenuate_ok(parent_hmac, child_rights);
}

/* Genuine JSON Formatters and Parsers */

OoStr json_format_string_internal(OoStr s) {
  size_t elen = 2;
  for (long long i = 0; i < s.len; i++) {
    char c = s.data[i];
    if (c == '"' || c == '\\') elen += 2;
    else if (c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') elen += 2;
    else if ((unsigned char)c < 32) elen += 6;
    else elen += 1;
  }
  /* ARC: headered payload so release can free safely. */
  char *buf = oo_str_alloc_payload(elen);
  buf[0] = '"'; size_t pos = 1;
  for (long long i = 0; i < s.len; i++) {
    char c = s.data[i];
    if (c == '"') { buf[pos++] = '\\'; buf[pos++] = '"'; }
    else if (c == '\\') { buf[pos++] = '\\'; buf[pos++] = '\\'; }
    else if (c == '\b') { buf[pos++] = '\\'; buf[pos++] = 'b'; }
    else if (c == '\f') { buf[pos++] = '\\'; buf[pos++] = 'f'; }
    else if (c == '\n') { buf[pos++] = '\\'; buf[pos++] = 'n'; }
    else if (c == '\r') { buf[pos++] = '\\'; buf[pos++] = 'r'; }
    else if (c == '\t') { buf[pos++] = '\\'; buf[pos++] = 't'; }
    else if ((unsigned char)c < 32) { pos += snprintf(buf + pos, sizeof(buf) - pos, "\\u%04x", (unsigned char)c); }
    else { buf[pos++] = c; }
  }
  buf[pos++] = '"'; buf[pos] = '\0';
  OoStr r; r.data = buf; r.len = (long long)pos; return r;
}

OoStr json_format_int_internal(long long v) {
  char buf[64]; snprintf(buf, sizeof buf, "%lld", v); return oo_str_lit(buf);
}

OoStr json_format_bool_internal(int b) {
  return b ? oo_str_lit("true") : oo_str_lit("false");
}

OoResS json_parse_internal(OoStr raw) {
  OoResS r;
  if (!raw.data || raw.len <= 0) {
    r.ok = 0; r.val = oo_str_lit("invalid json: empty");
    return r;
  }
  long long i = 0;
  while (i < raw.len && isspace((unsigned char)raw.data[i])) i++;
  if (i >= raw.len) {
    r.ok = 0; r.val = oo_str_lit("invalid json: whitespace only");
    return r;
  }
  long long last = raw.len - 1;
  while (last > i && isspace((unsigned char)raw.data[last])) last--;
  char first_ch = raw.data[i];
  char last_ch = raw.data[last];
  if (first_ch == '{') {
    if (last_ch != '}') {
      r.ok = 0; r.val = oo_str_lit("invalid json: unclosed brace");
      return r;
    }
  } else if (first_ch == '[') {
    if (last_ch != ']') {
      r.ok = 0; r.val = oo_str_lit("invalid json: unclosed bracket");
      return r;
    }
  } else if (first_ch == '"') {
    if (last_ch != '"' || last == i) {
      r.ok = 0; r.val = oo_str_lit("invalid json: unclosed string");
      return r;
    }
  } else if (isdigit((unsigned char)first_ch) || first_ch == '-' ||
             (i + 3 <= last && memcmp(raw.data + i, "true", 4) == 0) ||
             (i + 4 <= last && memcmp(raw.data + i, "false", 5) == 0) ||
             (i + 3 <= last && memcmp(raw.data + i, "null", 4) == 0)) {
    // Valid primitive literal
  } else {
    r.ok = 0; r.val = oo_str_lit("invalid json: unexpected character");
    return r;
  }
  r.ok = 1; r.val = raw;
  return r;
}

OoStr json_stringify_internal(OoStr obj) { return obj; }


OoResS python_embed_internal(long long sys, OoStr model) {
  oo_cap_require_sys(sys, "python_embed");
  (void)model; OoResS r; r.ok = 0; r.val = oo_str_lit("Err (Not Implemented)"); return r;
}

static pthread_once_t g_cg_sign_once = PTHREAD_ONCE_INIT;
static unsigned char g_cg_sign_key[32];

static void cg_sign_init(void) {
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(g_cg_sign_key, sizeof(g_cg_sign_key)) != 0)
#endif
  {
    unsigned long long acc = (unsigned long long)(uintptr_t)&g_cg_sign_key ^
                             ((unsigned long long)getpid() << 24) ^
                             (unsigned long long)oo_monotonic_us() ^
                             0x5A5A5A5AA5A5A5A5ULL;
    for (size_t i = 0; i < sizeof(g_cg_sign_key); i++) {
      acc = acc * 0x9E3779B97F4A7C15ULL + (unsigned long long)i + 0xDEADBEEFULL;
      g_cg_sign_key[i] = (unsigned char)(acc >> 16);
    }
  }
}

static long long oo_cg_calc_sig(long long cap) {
  pthread_once(&g_cg_sign_once, cg_sign_init);
  unsigned char k[64];
  memset(k, 0, sizeof(k));
  memcpy(k, g_cg_sign_key, sizeof(g_cg_sign_key));

  unsigned char ipad[64], opad[64];
  for (int i = 0; i < 64; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }

  unsigned char inner_buf[64 + 8];
  memcpy(inner_buf, ipad, 64);
  for (int i = 0; i < 8; i++) {
    inner_buf[64 + i] = (unsigned char)((uint64_t)cap >> ((7 - i) * 8));
  }

  unsigned char inner_digest[32];
  sha256_bytes(inner_buf, sizeof(inner_buf), inner_digest);
  crypto_secure_wipe(inner_buf, sizeof(inner_buf));

  unsigned char outer_buf[64 + 32];
  memcpy(outer_buf, opad, 64);
  memcpy(outer_buf + 64, inner_digest, 32);

  unsigned char outer_digest[32];
  sha256_bytes(outer_buf, sizeof(outer_buf), outer_digest);

  crypto_secure_wipe(k, sizeof(k));
  crypto_secure_wipe(ipad, sizeof(ipad));
  crypto_secure_wipe(opad, sizeof(opad));
  crypto_secure_wipe(outer_buf, sizeof(outer_buf));
  crypto_secure_wipe(inner_digest, sizeof(inner_digest));

  uint64_t sig = 0;
  for (int i = 0; i < 8; i++) {
    sig = (sig << 8) | (uint64_t)outer_digest[i];
  }
  crypto_secure_wipe(outer_digest, sizeof(outer_digest));
  return (long long)sig;
}

long long oo_cg_sign(long long cap) {
  oo_cap_require_sign(cap, "oo_cg_sign");
  return oo_cg_calc_sig(cap);
}

int oo_cg_verify(long long cap, long long sig) {
  oo_cap_require_sign(cap, "oo_cg_verify");
  if (sig == 0) return 0;
  long long expected = oo_cg_calc_sig(cap);
  int match = (crypto_ct_cmp(&sig, &expected, sizeof(long long)) == 0);
  crypto_secure_wipe(&expected, sizeof(expected));
  return match ? 1 : 0;
}
